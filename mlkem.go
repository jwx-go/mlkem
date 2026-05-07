// Package mlkem provides ML-KEM (FIPS 203) support for the jwx library.
//
// ML-KEM is a post-quantum key encapsulation mechanism. This module bridges
// Go's standard library [crypto/mlkem] (Go 1.24+) into jwx's algorithm
// registration system, enabling ML-KEM key types and JWE encryption /
// decryption with the AKP (Algorithm Key Pair) JWK key type.
//
// This exists as a separate module because the JOSE binding for ML-KEM is
// specified by draft-ietf-jose-pqc-kem, which is still an Internet-Draft.
// Once the draft is published as an RFC, this support may move directly into
// jwx and this module will be deprecated.
//
// Import this package for its side effects to enable ML-KEM support:
//
//	import _ "github.com/jwx-go/mlkem/v4"
//
// This registers ML-KEM-768/1024 (with and without AES key wrap) key
// encryption algorithms, JWK key import/export for the standard library
// ML-KEM key types, and JWE encrypt/decrypt dispatch via the jwebb extension
// hook.
//
// Registration happens in init(). If any underlying jwx Register* call
// returns an error, init() panics — importing this package will crash the
// program at load time. This is the house style across all jwx-go extension
// modules.
//
// Private ML-KEM JWKs store the 32-byte `d` seed in `priv`. This module also
// preserves the 32-byte implicit-rejection value in a companion-private `z`
// field so JWK round-trips can reconstruct the exact stdlib key. Legacy ML-KEM
// JWKs that only carry `priv` remain supported: on export, a deterministic `z`
// is derived from `d` and the ML-KEM parameter set.
package mlkem

import (
	"bytes"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe/jwebb"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwk/jwkunsafe"
)

const (
	algMLKEM768        = "ML-KEM-768"
	algMLKEM1024       = "ML-KEM-1024"
	algMLKEM768A192KW  = "ML-KEM-768+A192KW"
	algMLKEM1024A256KW = "ML-KEM-1024+A256KW"

	zFieldName          = "z"
	legacyZDerivePrefix = "jwx-go/mlkem z-derivation/"
)

// MLKEM768 returns the ML-KEM-768 key encryption algorithm (direct mode).
func MLKEM768() jwa.KeyEncryptionAlgorithm {
	return jwa.NewKeyEncryptionAlgorithm(algMLKEM768)
}

// MLKEM1024 returns the ML-KEM-1024 key encryption algorithm (direct mode).
func MLKEM1024() jwa.KeyEncryptionAlgorithm {
	return jwa.NewKeyEncryptionAlgorithm(algMLKEM1024)
}

// MLKEM768A192KW returns the ML-KEM-768 + AES-192 key wrap algorithm.
func MLKEM768A192KW() jwa.KeyEncryptionAlgorithm {
	return jwa.NewKeyEncryptionAlgorithm(algMLKEM768A192KW)
}

// MLKEM1024A256KW returns the ML-KEM-1024 + AES-256 key wrap algorithm.
func MLKEM1024A256KW() jwa.KeyEncryptionAlgorithm {
	return jwa.NewKeyEncryptionAlgorithm(algMLKEM1024A256KW)
}

func allAlgs() []string {
	return []string{algMLKEM768, algMLKEM1024, algMLKEM768A192KW, algMLKEM1024A256KW}
}

func directAlgs() []string {
	return []string{algMLKEM768, algMLKEM1024}
}

func isDirectAlg(alg string) bool {
	return alg == algMLKEM768 || alg == algMLKEM1024
}

// kdfAlgorithmID returns the algorithm identifier string used in the
// KMAC256 KDF. For direct mode this is the content encryption algorithm;
// for key-wrap mode this is the key encryption algorithm itself.
func kdfAlgorithmID(alg, calg string) string {
	if isDirectAlg(alg) {
		return calg
	}
	return alg
}

// derivedKeySize returns the KDF output size for the given ML-KEM
// algorithm and content encryption algorithm.
func derivedKeySize(alg, calg string) (int, error) {
	if isDirectAlg(alg) {
		return cekSize(calg)
	}
	switch alg {
	case algMLKEM768A192KW:
		return 24, nil
	case algMLKEM1024A256KW:
		return 32, nil
	default:
		return 0, fmt.Errorf(`mlkem: unsupported algorithm %q`, alg)
	}
}

func cekSize(calg string) (int, error) {
	switch calg {
	case "A128GCM":
		return 16, nil
	case "A192GCM":
		return 24, nil
	case "A256GCM":
		return 32, nil
	case "A128CBC-HS256":
		return 32, nil
	case "A192CBC-HS384":
		return 48, nil
	case "A256CBC-HS512":
		return 64, nil
	default:
		return 0, fmt.Errorf(`mlkem: unsupported content encryption algorithm %q`, calg)
	}
}

func init() {
	panicOnRegistrationError(jwa.RegisterKeyEncryptionAlgorithm(MLKEM768(), MLKEM1024(), MLKEM768A192KW(), MLKEM1024A256KW()))

	for _, alg := range allAlgs() {
		panicOnRegistrationError(jwebb.RegisterMLKEMAlgorithm(alg))
	}
	for _, alg := range directAlgs() {
		panicOnRegistrationError(jwebb.RegisterMLKEMDirectAlgorithm(alg))
	}

	panicOnRegistrationError(jwk.RegisterCustomDecoder(zFieldName, jwk.CustomDecodeFunc[[]byte](decodeBase64Bytes)))
	panicOnRegistrationError(jwk.RegisterKeyImporter(jwk.KeyImportFunc[*mlkem.EncapsulationKey768](importEncapsulationKey768)))
	panicOnRegistrationError(jwk.RegisterKeyImporter(jwk.KeyImportFunc[*mlkem.EncapsulationKey1024](importEncapsulationKey1024)))
	panicOnRegistrationError(jwk.RegisterKeyImporter(jwk.KeyImportFunc[*mlkem.DecapsulationKey768](importDecapsulationKey768)))
	panicOnRegistrationError(jwk.RegisterKeyImporter(jwk.KeyImportFunc[*mlkem.DecapsulationKey1024](importDecapsulationKey1024)))

	// Register a per-algorithm exporter for every ML-KEM AKP variant.
	// jwx v4's AKP KeyKind at export time is "AKP:" + the "alg" field
	// currently stored on the JWK (see jwk/akp.go akpKeyKind), so which
	// of the four KeyKinds a key lands on depends on how it was built:
	//
	//   - Keys imported from a stdlib *mlkem.{Encap,Decap}sulationKey*
	//     via our importers above store the bare KEM name and land on
	//     "AKP:ML-KEM-768" or "AKP:ML-KEM-1024".
	//   - Keys produced by unmarshalling a JSON JWK (jwk.Parse) or by
	//     rewriting the alg via key.Set carry whatever alg the caller
	//     chose. Per draft-ietf-jose-pqc-kem that may legitimately be a
	//     +KW variant, and such keys land on "AKP:ML-KEM-768+A192KW" or
	//     "AKP:ML-KEM-1024+A256KW".
	//
	// All four KeyKinds are therefore real exporter targets and must be
	// registered. The +KW pair is pinned by TestExportWithKWAlg in
	// mlkem_test.go so a future refactor cannot delete them silently.
	for _, alg := range []string{algMLKEM768, algMLKEM1024, algMLKEM768A192KW, algMLKEM1024A256KW} {
		panicOnRegistrationError(jwk.RegisterKeyExporter(jwk.KeyKind("AKP:"+alg), jwk.KeyExportFunc(exportMLKEMKey)))
	}
}

// panicOnRegistrationError converts a non-nil error returned by a jwx
// Register* call during init() into an import-time panic. The rule
// (documented in jwx's internals.md) is that a failed Register* leaves
// the extension unusable, so we surface it immediately instead of
// letting the program continue in a broken state.
func panicOnRegistrationError(err error) {
	if err != nil {
		panic(fmt.Sprintf("jwx-go/mlkem: registration failed: %s", err))
	}
}

func importEncapsulationKey768(raw *mlkem.EncapsulationKey768) (jwk.Key, error) {
	return importPublic(raw.Bytes(), algMLKEM768)
}

func importEncapsulationKey1024(raw *mlkem.EncapsulationKey1024) (jwk.Key, error) {
	return importPublic(raw.Bytes(), algMLKEM1024)
}

func importDecapsulationKey768(raw *mlkem.DecapsulationKey768) (jwk.Key, error) {
	seed := raw.Bytes() // 64-byte d || z
	return importPrivate(raw.EncapsulationKey().Bytes(), seed[:32], seed[32:], algMLKEM768)
}

func importDecapsulationKey1024(raw *mlkem.DecapsulationKey1024) (jwk.Key, error) {
	seed := raw.Bytes()
	return importPrivate(raw.EncapsulationKey().Bytes(), seed[:32], seed[32:], algMLKEM1024)
}

func importPublic(pub []byte, alg string) (jwk.Key, error) {
	key, err := jwkunsafe.NewPublicKey(jwa.AKP())
	if err != nil {
		return nil, fmt.Errorf(`mlkem import: %w`, err)
	}
	if err := key.Set(jwk.AlgorithmKey, alg); err != nil {
		return nil, fmt.Errorf(`mlkem import: %w`, err)
	}
	if err := key.Set(jwk.AKPPubKey, pub); err != nil {
		return nil, fmt.Errorf(`mlkem import: %w`, err)
	}
	return key, nil
}

// importPrivate builds an AKP jwk.Key from a pub/priv/z byte triple. It is only
// reachable from importDecapsulationKey768/1024 above, both of which pass
// raw.EncapsulationKey().Bytes() for pub — i.e. the public key derived from
// the same stdlib *mlkem.DecapsulationKey that produced priv. The pub/priv
// consistency check therefore lives one layer up in newDecapsulation768/1024
// (called from the exporter on the way back out). A JSON-parsed JWK with a
// mismatched pub never flows through this function: jwx core unmarshals AKP
// keys directly into a jwk.Key without calling our per-package importers,
// and the inconsistency is caught at export time instead.
func importPrivate(pub, priv, z []byte, alg string) (jwk.Key, error) {
	key, err := jwkunsafe.NewKey(jwa.AKP())
	if err != nil {
		return nil, fmt.Errorf(`mlkem import: %w`, err)
	}
	if err := key.Set(jwk.AlgorithmKey, alg); err != nil {
		return nil, fmt.Errorf(`mlkem import: %w`, err)
	}
	if err := key.Set(jwk.AKPPubKey, pub); err != nil {
		return nil, fmt.Errorf(`mlkem import: %w`, err)
	}
	if err := key.Set(jwk.AKPPrivKey, priv); err != nil {
		return nil, fmt.Errorf(`mlkem import: %w`, err)
	}
	if err := key.Set(zFieldName, z); err != nil {
		return nil, fmt.Errorf(`mlkem import: %w`, err)
	}
	return key, nil
}

// exportMLKEMKey converts an AKP jwk.Key into the requested raw form.
//
// The hint argument from jwk.Export[T] is the zero value of T:
//   - For interface T (jwebb.MLKEMKeyEncrypter, MLKEMKeyDecrypter), hint
//     is a nil interface and we return a wrapper struct that implements
//     both interfaces.
//   - For concrete T (e.g. *mlkem.EncapsulationKey768), hint is a
//     typed-nil pointer and we return the matching stdlib key value.
func exportMLKEMKey(key jwk.Key, hint any) (any, error) {
	algV, ok := key.Algorithm()
	if !ok {
		return nil, fmt.Errorf(`mlkem export: missing "alg" field`)
	}
	alg := algV.String()

	switch alg {
	case algMLKEM768, algMLKEM1024, algMLKEM768A192KW, algMLKEM1024A256KW:
	default:
		return nil, jwk.ContinueError()
	}

	pubV, ok := key.Field(jwk.AKPPubKey)
	if !ok {
		return nil, fmt.Errorf(`mlkem export: missing "pub" field`)
	}
	pub, ok := pubV.([]byte)
	if !ok {
		return nil, fmt.Errorf(`mlkem export: "pub" field is not []byte`)
	}

	priv, hasPriv, err := keyFieldBytes(key, jwk.AKPPrivKey)
	if err != nil {
		return nil, err
	}

	z, hasZ, err := keyFieldBytes(key, zFieldName)
	if err != nil {
		return nil, err
	}
	if hasZ && !hasPriv {
		return nil, fmt.Errorf(`mlkem export: %q field requires %q field`, zFieldName, jwk.AKPPrivKey)
	}
	if hasZ && len(z) != 32 {
		return nil, fmt.Errorf(`mlkem export: %q field must be 32 bytes, got %d`, zFieldName, len(z))
	}

	switch hint.(type) {
	case *mlkem.EncapsulationKey768:
		return mlkem.NewEncapsulationKey768(pub)
	case *mlkem.EncapsulationKey1024:
		return mlkem.NewEncapsulationKey1024(pub)
	case *mlkem.DecapsulationKey768:
		dk, err := newDecapsulation768(pub, priv, z)
		if err != nil {
			return nil, err
		}
		return dk, nil
	case *mlkem.DecapsulationKey1024:
		dk, err := newDecapsulation1024(pub, priv, z)
		if err != nil {
			return nil, err
		}
		return dk, nil
	}

	// Interface or unknown target — build the wrapper that implements
	// both jwebb.MLKEMKeyEncrypter and jwebb.MLKEMKeyDecrypter.
	wrapper := &mlkemKey{alg: bareAlg(alg)}

	switch bareAlg(alg) {
	case algMLKEM768:
		ek, err := mlkem.NewEncapsulationKey768(pub)
		if err != nil {
			return nil, fmt.Errorf(`mlkem export: %w`, err)
		}
		wrapper.encap = ek
		if priv != nil {
			dk, err := newDecapsulation768(pub, priv, z)
			if err != nil {
				return nil, err
			}
			wrapper.decap = dk
		}
	case algMLKEM1024:
		ek, err := mlkem.NewEncapsulationKey1024(pub)
		if err != nil {
			return nil, fmt.Errorf(`mlkem export: %w`, err)
		}
		wrapper.encap = ek
		if priv != nil {
			dk, err := newDecapsulation1024(pub, priv, z)
			if err != nil {
				return nil, err
			}
			wrapper.decap = dk
		}
	}

	return wrapper, nil
}

// bareAlg strips the "+AnnnKW" suffix from a key encryption algorithm
// identifier, returning the bare KEM name.
func bareAlg(alg string) string {
	switch alg {
	case algMLKEM768, algMLKEM768A192KW:
		return algMLKEM768
	case algMLKEM1024, algMLKEM1024A256KW:
		return algMLKEM1024
	}
	return alg
}

// decodeBase64Bytes decodes a JSON string into its raw base64url
// payload. The "z" field of an mlkem AKP JWK is decoded through this
// function via jwk.RegisterCustomDecoder.
//
// Per RFC 7515 §2 and the JOSE convention adopted across draft-
// ietf-jose-pqc-kem, JWK byte fields use base64url WITHOUT padding.
// A permissive decoder that also accepts std encoding or padded
// forms creates JWK acceptance ambiguity: two byte-distinct
// representations of the same key both decode successfully, which
// breaks JWK fingerprint hashing, dedup caches keyed on the JWK
// bytes, and any downstream "compare-as-bytes-then-hash" validator.
//
// This module's exporter always emits raw base64url (jwx core's
// canonical JWK encoding), and the "z" field is a companion-private
// extension — there are no third-party producers — so tightening
// the import path to match is safe.
func decodeBase64Bytes(data []byte) ([]byte, error) {
	var encoded string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return nil, err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf(`mlkem: "z" field must be base64url-encoded without padding (RFC 7515 §2): %w`, err)
	}
	return decoded, nil
}

func keyFieldBytes(key jwk.Key, field string) ([]byte, bool, error) {
	v, ok := key.Field(field)
	if !ok {
		return nil, false, nil
	}
	b, ok := v.([]byte)
	if !ok {
		return nil, true, fmt.Errorf(`mlkem export: %q field is not []byte`, field)
	}
	return b, true, nil
}

func deriveLegacyZ(priv []byte, alg string) ([]byte, error) {
	z, err := hkdf.Key(sha256.New, priv, nil, legacyZDerivePrefix+alg, 32)
	if err != nil {
		return nil, fmt.Errorf(`mlkem: failed to derive deterministic z for legacy %s JWK: %w`, alg, err)
	}
	return z, nil
}

func seedForDecapsulation(priv, z []byte, alg string) ([]byte, error) {
	if len(priv) != 32 {
		return nil, fmt.Errorf(`mlkem: %s priv must be 32 bytes, got %d`, alg, len(priv))
	}
	if z == nil {
		var err error
		z, err = deriveLegacyZ(priv, alg)
		if err != nil {
			return nil, err
		}
	}
	if len(z) != 32 {
		return nil, fmt.Errorf(`mlkem: %s z must be 32 bytes, got %d`, alg, len(z))
	}

	seed := make([]byte, 64)
	copy(seed[:32], priv)
	copy(seed[32:], z)
	return seed, nil
}

// newDecapsulation768 reconstructs an ML-KEM-768 decapsulation key from the
// stored 32-byte d seed and either the preserved `z` field or a deterministic
// fallback for legacy JWKs that only carry `priv`.
func newDecapsulation768(pub, priv, z []byte) (*mlkem.DecapsulationKey768, error) {
	seed, err := seedForDecapsulation(priv, z, algMLKEM768)
	if err != nil {
		return nil, err
	}
	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return nil, fmt.Errorf(`mlkem: failed to construct ML-KEM-768 decapsulation key: %w`, err)
	}
	if !bytes.Equal(dk.EncapsulationKey().Bytes(), pub) {
		return nil, fmt.Errorf(`mlkem: "pub" field does not match key derived from "priv"`)
	}
	return dk, nil
}

func newDecapsulation1024(pub, priv, z []byte) (*mlkem.DecapsulationKey1024, error) {
	seed, err := seedForDecapsulation(priv, z, algMLKEM1024)
	if err != nil {
		return nil, err
	}
	dk, err := mlkem.NewDecapsulationKey1024(seed)
	if err != nil {
		return nil, fmt.Errorf(`mlkem: failed to construct ML-KEM-1024 decapsulation key: %w`, err)
	}
	if !bytes.Equal(dk.EncapsulationKey().Bytes(), pub) {
		return nil, fmt.Errorf(`mlkem: "pub" field does not match key derived from "priv"`)
	}
	return dk, nil
}
