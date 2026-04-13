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
package mlkem

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe/jwebb"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwk/jwkunsafe"
)

const (
	algMLKEM768       = "ML-KEM-768"
	algMLKEM1024      = "ML-KEM-1024"
	algMLKEM768A192KW = "ML-KEM-768+A192KW"
	algMLKEM1024A256  = "ML-KEM-1024+A256KW"
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
	return jwa.NewKeyEncryptionAlgorithm(algMLKEM1024A256)
}

func allAlgs() []string {
	return []string{algMLKEM768, algMLKEM1024, algMLKEM768A192KW, algMLKEM1024A256}
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
	case algMLKEM1024A256:
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
	jwa.RegisterKeyEncryptionAlgorithm(MLKEM768(), MLKEM1024(), MLKEM768A192KW(), MLKEM1024A256KW())

	for _, alg := range allAlgs() {
		jwebb.RegisterMLKEMAlgorithm(alg)
	}
	for _, alg := range directAlgs() {
		jwebb.RegisterMLKEMDirectAlgorithm(alg)
	}

	jwk.RegisterKeyImporter(importEncapsulationKey768)
	jwk.RegisterKeyImporter(importEncapsulationKey1024)
	jwk.RegisterKeyImporter(importDecapsulationKey768)
	jwk.RegisterKeyImporter(importDecapsulationKey1024)

	// Register a per-algorithm exporter for every ML-KEM AKP variant.
	// jwx v4's AKP key returns KeyKind "AKP:<alg>", and the alg string
	// stored on the JWK uses the bare KEM name even for the +KW variants
	// (the JWK only describes the key, not the wrap mode), so we register
	// the bare names plus the +KW names defensively.
	for _, alg := range []string{algMLKEM768, algMLKEM1024, algMLKEM768A192KW, algMLKEM1024A256} {
		jwk.RegisterKeyExporter(jwk.KeyKind("AKP:"+alg), jwk.KeyExportFunc(exportMLKEMKey))
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
	return importPrivate(raw.EncapsulationKey().Bytes(), seed[:32], algMLKEM768)
}

func importDecapsulationKey1024(raw *mlkem.DecapsulationKey1024) (jwk.Key, error) {
	seed := raw.Bytes()
	return importPrivate(raw.EncapsulationKey().Bytes(), seed[:32], algMLKEM1024)
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

func importPrivate(pub, priv []byte, alg string) (jwk.Key, error) {
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
	case algMLKEM768, algMLKEM1024, algMLKEM768A192KW, algMLKEM1024A256:
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

	var priv []byte
	if privV, hasPriv := key.Field(jwk.AKPPrivKey); hasPriv {
		pb, ok := privV.([]byte)
		if !ok {
			return nil, fmt.Errorf(`mlkem export: "priv" field is not []byte`)
		}
		priv = pb
	}

	switch hint.(type) {
	case *mlkem.EncapsulationKey768:
		return mlkem.NewEncapsulationKey768(pub)
	case *mlkem.EncapsulationKey1024:
		return mlkem.NewEncapsulationKey1024(pub)
	case *mlkem.DecapsulationKey768:
		dk, err := newDecapsulation768(pub, priv)
		if err != nil {
			return nil, err
		}
		return dk, nil
	case *mlkem.DecapsulationKey1024:
		dk, err := newDecapsulation1024(pub, priv)
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
			dk, err := newDecapsulation768(pub, priv)
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
			dk, err := newDecapsulation1024(pub, priv)
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
	case algMLKEM1024, algMLKEM1024A256:
		return algMLKEM1024
	}
	return alg
}

// newDecapsulation768 reconstructs an ML-KEM-768 decapsulation key from a
// 32-byte d seed plus the expected encapsulation key bytes for round-trip
// verification. A fresh random z is generated for implicit rejection (see
// the interoperability note in the package doc / README).
func newDecapsulation768(pub, priv []byte) (*mlkem.DecapsulationKey768, error) {
	if len(priv) != 32 {
		return nil, fmt.Errorf(`mlkem: ML-KEM-768 priv must be 32 bytes, got %d`, len(priv))
	}
	seed := make([]byte, 64)
	copy(seed[:32], priv)
	if _, err := rand.Read(seed[32:]); err != nil {
		return nil, fmt.Errorf(`mlkem: failed to generate random z: %w`, err)
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

func newDecapsulation1024(pub, priv []byte) (*mlkem.DecapsulationKey1024, error) {
	if len(priv) != 32 {
		return nil, fmt.Errorf(`mlkem: ML-KEM-1024 priv must be 32 bytes, got %d`, len(priv))
	}
	seed := make([]byte, 64)
	copy(seed[:32], priv)
	if _, err := rand.Read(seed[32:]); err != nil {
		return nil, fmt.Errorf(`mlkem: failed to generate random z: %w`, err)
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
