package mlkem_test

import (
	"bytes"
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"testing"

	jwxmlkem "github.com/jwx-go/mlkem/v4"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/lestrrat-go/jwx/v4/jwe/jwebb"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

func TestMLKEM(t *testing.T) {
	payload := []byte("Hello, post-quantum world!")

	t.Run("ML-KEM-768 direct", func(t *testing.T) {
		dk, err := mlkem.GenerateKey768()
		require.NoError(t, err)

		ek := dk.EncapsulationKey()

		encrypted, err := jwe.Encrypt(payload,
			jwe.WithKey(jwxmlkem.MLKEM768(), ek),
			jwe.WithContentEncryption(jwa.A256GCM()),
		)
		require.NoError(t, err, "Encrypt should succeed")

		decrypted, err := jwe.Decrypt(encrypted,
			jwe.WithKey(jwxmlkem.MLKEM768(), dk),
		)
		require.NoError(t, err, "Decrypt should succeed")
		require.Equal(t, payload, decrypted)
	})

	t.Run("ML-KEM-1024 direct", func(t *testing.T) {
		dk, err := mlkem.GenerateKey1024()
		require.NoError(t, err)

		ek := dk.EncapsulationKey()

		encrypted, err := jwe.Encrypt(payload,
			jwe.WithKey(jwxmlkem.MLKEM1024(), ek),
			jwe.WithContentEncryption(jwa.A256GCM()),
		)
		require.NoError(t, err, "Encrypt should succeed")

		decrypted, err := jwe.Decrypt(encrypted,
			jwe.WithKey(jwxmlkem.MLKEM1024(), dk),
		)
		require.NoError(t, err, "Decrypt should succeed")
		require.Equal(t, payload, decrypted)
	})

	t.Run("ML-KEM-768+A192KW key wrap", func(t *testing.T) {
		dk, err := mlkem.GenerateKey768()
		require.NoError(t, err)

		ek := dk.EncapsulationKey()

		encrypted, err := jwe.Encrypt(payload,
			jwe.WithKey(jwxmlkem.MLKEM768A192KW(), ek),
			jwe.WithContentEncryption(jwa.A256GCM()),
		)
		require.NoError(t, err, "Encrypt should succeed")

		decrypted, err := jwe.Decrypt(encrypted,
			jwe.WithKey(jwxmlkem.MLKEM768A192KW(), dk),
		)
		require.NoError(t, err, "Decrypt should succeed")
		require.Equal(t, payload, decrypted)
	})

	t.Run("ML-KEM-1024+A256KW key wrap", func(t *testing.T) {
		dk, err := mlkem.GenerateKey1024()
		require.NoError(t, err)

		ek := dk.EncapsulationKey()

		encrypted, err := jwe.Encrypt(payload,
			jwe.WithKey(jwxmlkem.MLKEM1024A256KW(), ek),
			jwe.WithContentEncryption(jwa.A256GCM()),
		)
		require.NoError(t, err, "Encrypt should succeed")

		decrypted, err := jwe.Decrypt(encrypted,
			jwe.WithKey(jwxmlkem.MLKEM1024A256KW(), dk),
		)
		require.NoError(t, err, "Decrypt should succeed")
		require.Equal(t, payload, decrypted)
	})

	t.Run("ML-KEM-768 key mismatch with ML-KEM-1024", func(t *testing.T) {
		dk768, err := mlkem.GenerateKey768()
		require.NoError(t, err)

		dk1024, err := mlkem.GenerateKey1024()
		require.NoError(t, err)

		encrypted, err := jwe.Encrypt(payload,
			jwe.WithKey(jwxmlkem.MLKEM768(), dk768.EncapsulationKey()),
			jwe.WithContentEncryption(jwa.A256GCM()),
		)
		require.NoError(t, err)

		_, err = jwe.Decrypt(encrypted,
			jwe.WithKey(jwxmlkem.MLKEM768(), dk1024),
		)
		require.Error(t, err, "Decrypt with wrong key type should fail")
	})

	t.Run("ML-KEM with different content encryption algorithms", func(t *testing.T) {
		dk, err := mlkem.GenerateKey768()
		require.NoError(t, err)

		for _, calg := range []jwa.ContentEncryptionAlgorithm{
			jwa.A128GCM(),
			jwa.A192GCM(),
			jwa.A256GCM(),
			jwa.A128CBC_HS256(),
			jwa.A256CBC_HS512(),
		} {
			t.Run(calg.String(), func(t *testing.T) {
				encrypted, err := jwe.Encrypt(payload,
					jwe.WithKey(jwxmlkem.MLKEM768(), dk.EncapsulationKey()),
					jwe.WithContentEncryption(calg),
				)
				require.NoError(t, err, "Encrypt should succeed")

				decrypted, err := jwe.Decrypt(encrypted,
					jwe.WithKey(jwxmlkem.MLKEM768(), dk),
				)
				require.NoError(t, err, "Decrypt should succeed")
				require.Equal(t, payload, decrypted)
			})
		}
	})

	t.Run("JWK round-trip via jwk.Import / jwk.Export", func(t *testing.T) {
		dk, err := mlkem.GenerateKey768()
		require.NoError(t, err)
		seed := dk.Bytes()

		jkey, err := jwk.Import[jwk.Key](dk)
		require.NoError(t, err)

		require.Equal(t, jwa.AKP(), jkey.KeyType())
		alg, ok := jkey.Algorithm()
		require.True(t, ok)
		require.Equal(t, "ML-KEM-768", alg.String())
		z, ok := jkey.Field("z")
		require.True(t, ok)
		require.Equal(t, seed[32:], z)

		// Round-trip back to a raw decapsulation key.
		exported, err := jwk.Export[*mlkem.DecapsulationKey768](jkey)
		require.NoError(t, err)
		require.Equal(t, seed, exported.Bytes())
		require.Equal(t, dk.EncapsulationKey().Bytes(), exported.EncapsulationKey().Bytes())

		pubJWK, err := jkey.PublicKey()
		require.NoError(t, err)
		require.False(t, pubJWK.Has("z"))

		// Encrypt with public JWK, decrypt with private JWK.
		encrypted, err := jwe.Encrypt(payload,
			jwe.WithKey(jwxmlkem.MLKEM768(), pubJWK),
			jwe.WithContentEncryption(jwa.A256GCM()),
		)
		require.NoError(t, err)

		decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwxmlkem.MLKEM768(), jkey))
		require.NoError(t, err)
		require.Equal(t, payload, decrypted)
	})
}

func TestLegacyJWKWithoutZUsesDeterministicFallback(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	require.NoError(t, err)

	jkey, err := jwk.Import[jwk.Key](dk)
	require.NoError(t, err)
	require.NoError(t, jkey.Remove("z"))

	buf, err := json.Marshal(jkey)
	require.NoError(t, err)

	parsed1, err := jwk.ParseKeyAs[jwk.Key](buf)
	require.NoError(t, err)
	parsed2, err := jwk.ParseKeyAs[jwk.Key](buf)
	require.NoError(t, err)

	exported1, err := jwk.Export[*mlkem.DecapsulationKey768](parsed1)
	require.NoError(t, err)
	exported2, err := jwk.Export[*mlkem.DecapsulationKey768](parsed2)
	require.NoError(t, err)

	require.Equal(t, exported1.Bytes(), exported2.Bytes())
	require.Equal(t, dk.Bytes()[:32], exported1.Bytes()[:32])
	require.Equal(t, dk.EncapsulationKey().Bytes(), exported1.EncapsulationKey().Bytes())
}

// TestExportWithKWAlg pins the +KW KeyKind exporter registrations in
// mlkem.go's init(). A JWK whose "alg" field is "ML-KEM-768+A192KW" (or
// "ML-KEM-1024+A256KW") produces KeyKind "AKP:ML-KEM-768+A192KW" (or
// "AKP:ML-KEM-1024+A256KW") via jwk/akp.go akpKeyKind, so jwk.Export
// dispatches to the +KW registrations — not the bare-name ones. This
// test fails with an unregistered-KeyKind error if those entries are
// dropped from the registration loop.
func TestExportWithKWAlg(t *testing.T) {
	testcases := []struct {
		name    string
		alg     jwa.KeyEncryptionAlgorithm
		genDK   func() (any, error)
		exportT func(jwk.Key) error
	}{
		{
			name:  "ML-KEM-768+A192KW",
			alg:   jwxmlkem.MLKEM768A192KW(),
			genDK: func() (any, error) { return mlkem.GenerateKey768() },
			exportT: func(k jwk.Key) error {
				_, err := jwk.Export[*mlkem.DecapsulationKey768](k)
				return err
			},
		},
		{
			name:  "ML-KEM-1024+A256KW",
			alg:   jwxmlkem.MLKEM1024A256KW(),
			genDK: func() (any, error) { return mlkem.GenerateKey1024() },
			exportT: func(k jwk.Key) error {
				_, err := jwk.Export[*mlkem.DecapsulationKey1024](k)
				return err
			},
		},
	}

	payload := []byte("Hello, post-quantum world!")

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := tc.genDK()
			require.NoError(t, err)

			jkey, err := jwk.Import[jwk.Key](raw)
			require.NoError(t, err)

			// Rewrite alg to the +KW variant so KeyKind becomes
			// "AKP:<tc.name>" and export dispatches to the +KW
			// exporter registration.
			require.NoError(t, jkey.Set(jwk.AlgorithmKey, tc.alg.String()))

			require.NoError(t, tc.exportT(jkey), "export to stdlib key type should succeed via +KW KeyKind")

			dec, err := jwk.Export[jwebb.MLKEMKeyDecrypter](jkey)
			require.NoError(t, err, "export to MLKEMKeyDecrypter should succeed via +KW KeyKind")
			require.NotNil(t, dec)

			enc, err := jwk.Export[jwebb.MLKEMKeyEncrypter](jkey)
			require.NoError(t, err, "export to MLKEMKeyEncrypter should succeed via +KW KeyKind")
			require.NotNil(t, enc)

			// End-to-end: encrypt/decrypt through the JWK.
			pubJWK, err := jkey.PublicKey()
			require.NoError(t, err)

			encrypted, err := jwe.Encrypt(payload,
				jwe.WithKey(tc.alg, pubJWK),
				jwe.WithContentEncryption(jwa.A256GCM()),
			)
			require.NoError(t, err)

			decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(tc.alg, jkey))
			require.NoError(t, err)
			require.Equal(t, payload, decrypted)
		})
	}
}

func TestAlgVariantMismatch(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	require.NoError(t, err)

	jkey, err := jwk.Import[jwk.Key](dk)
	require.NoError(t, err)

	enc, err := jwk.Export[jwebb.MLKEMKeyEncrypter](jkey)
	require.NoError(t, err)
	dec, err := jwk.Export[jwebb.MLKEMKeyDecrypter](jkey)
	require.NoError(t, err)

	cek := make([]byte, 32)

	t.Run("EncryptMLKEM rejects mismatched alg", func(t *testing.T) {
		_, _, err := enc.EncryptMLKEM(cek, "ML-KEM-1024", "A256GCM")
		require.Error(t, err)
		require.Contains(t, err.Error(), "ML-KEM-1024")
		require.Contains(t, err.Error(), "ML-KEM-768")
	})

	t.Run("EncryptMLKEM rejects mismatched +KW alg", func(t *testing.T) {
		_, _, err := enc.EncryptMLKEM(cek, "ML-KEM-1024+A256KW", "A256GCM")
		require.Error(t, err)
	})

	t.Run("DecryptMLKEM rejects mismatched alg", func(t *testing.T) {
		_, err := dec.DecryptMLKEM(nil, "ML-KEM-1024", "A256GCM", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "ML-KEM-1024")
		require.Contains(t, err.Error(), "ML-KEM-768")
	})

	t.Run("matching alg still succeeds", func(t *testing.T) {
		_, kemCT, err := enc.EncryptMLKEM(cek, "ML-KEM-768", "A256GCM")
		require.NoError(t, err)
		// Direct-mode JWE encrypted_key is empty per spec (and per
		// jwebb.IsDirectCEK in main jwx); pass nil sealedCEK to match
		// the real wire shape.
		_, err = dec.DecryptMLKEM(nil, "ML-KEM-768", "A256GCM", kemCT)
		require.NoError(t, err)
	})
}

// TestDirectModeRejectsNonEmptyEncryptedKey pins the contract that
// direct-mode DecryptMLKEM rejects a non-empty sealedCEK (the JWE
// "encrypted_key" field). Per draft-ietf-jose-pqc-kem, direct-mode
// encrypted_key MUST be empty; main jwx already produces empty
// encrypted_key for direct ML-KEM (gated by jwebb.IsDirectCEK), so
// the regression case is a tampering proxy or buggy peer that
// inserts bytes there. Without the guard, the bytes would be
// silently discarded.
func TestDirectModeRejectsNonEmptyEncryptedKey(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	require.NoError(t, err)

	jkey, err := jwk.Import[jwk.Key](dk)
	require.NoError(t, err)

	enc, err := jwk.Export[jwebb.MLKEMKeyEncrypter](jkey)
	require.NoError(t, err)
	dec, err := jwk.Export[jwebb.MLKEMKeyDecrypter](jkey)
	require.NoError(t, err)

	cek := make([]byte, 32)
	derivedCEK, kemCT, err := enc.EncryptMLKEM(cek, "ML-KEM-768", "A256GCM")
	require.NoError(t, err)
	require.NotEmpty(t, derivedCEK)
	require.NotEmpty(t, kemCT)

	t.Run("non-empty sealedCEK is rejected in direct mode", func(t *testing.T) {
		_, err := dec.DecryptMLKEM([]byte("not-empty"), "ML-KEM-768", "A256GCM", kemCT)
		require.Error(t, err, "direct alg must require empty encrypted_key")
		require.Contains(t, err.Error(), "empty encrypted_key",
			"error must name the spec violation")
	})

	t.Run("empty sealedCEK in direct mode succeeds", func(t *testing.T) {
		recovered, err := dec.DecryptMLKEM(nil, "ML-KEM-768", "A256GCM", kemCT)
		require.NoError(t, err)
		require.Equal(t, derivedCEK, recovered,
			"DecryptMLKEM in direct mode returns the KDF-derived CEK")
	})

	t.Run("zero-length non-nil sealedCEK in direct mode succeeds", func(t *testing.T) {
		recovered, err := dec.DecryptMLKEM([]byte{}, "ML-KEM-768", "A256GCM", kemCT)
		require.NoError(t, err)
		require.Equal(t, derivedCEK, recovered)
	})

	t.Run("wrap-mode round-trip still accepts non-empty sealedCEK", func(t *testing.T) {
		// Sanity-check the guard doesn't fire for +KW algs.
		require.NoError(t, jkey.Set(jwk.AlgorithmKey, "ML-KEM-768+A192KW"))

		encKW, err := jwk.Export[jwebb.MLKEMKeyEncrypter](jkey)
		require.NoError(t, err)
		decKW, err := jwk.Export[jwebb.MLKEMKeyDecrypter](jkey)
		require.NoError(t, err)

		sealed, kemCTKW, err := encKW.EncryptMLKEM(cek, "ML-KEM-768+A192KW", "A192GCM")
		require.NoError(t, err)
		require.NotEmpty(t, sealed, "wrap mode emits an AES-KW envelope, not empty")

		recovered, err := decKW.DecryptMLKEM(sealed, "ML-KEM-768+A192KW", "A192GCM", kemCTKW)
		require.NoError(t, err)
		require.Equal(t, cek, recovered)
	})
}

// TestZFieldBase64Strictness pins the contract that the "z" custom
// decoder accepts only RFC 7515 §2 base64url-without-padding —
// rejecting std encoding, URL-with-padding, and std-with-padding.
//
// The "z" field is a companion-private extension; the only producer
// is this module's own exporter, which always emits raw base64url.
// Accepting other forms creates JWK acceptance ambiguity (two
// byte-distinct representations of the same key) which breaks JWK
// fingerprint hashing and similar identity-by-bytes patterns.
func TestZFieldBase64Strictness(t *testing.T) {
	// Build a minimal AKP private-key JWK JSON with a known 32-byte
	// "z" payload. The companion's exporter would emit this as raw
	// base64url; we then swap the "z" value to other encodings and
	// verify each is rejected.
	dk, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	jkey, err := jwk.Import[jwk.Key](dk)
	require.NoError(t, err)

	canonical, err := json.Marshal(jkey)
	require.NoError(t, err)

	// Extract the canonical (raw URL) encoded value of "z" from the
	// marshaled JWK so we can build re-encoded variants of the same
	// 32 bytes.
	var raw map[string]any
	require.NoError(t, json.Unmarshal(canonical, &raw))
	rawURLZ, ok := raw["z"].(string)
	require.True(t, ok, "z must be present and a string in the canonical JSON")

	// Decode the canonical "z" back to the underlying 32 bytes.
	zBytes, err := base64.RawURLEncoding.DecodeString(rawURLZ)
	require.NoError(t, err, "canonical z must round-trip through RawURLEncoding")
	require.Len(t, zBytes, 32, "z is 32 bytes per FIPS 203")

	// Build a JWK JSON with a parameterized "z" encoding. We rebuild
	// the JSON by swapping the "z" field rather than reusing
	// canonical-with-replacement, to avoid escaping pitfalls.
	rebuild := func(zValue string) []byte {
		raw["z"] = zValue
		out, mErr := json.Marshal(raw)
		require.NoError(t, mErr)
		return out
	}

	t.Run("RawURL encoding accepted (control)", func(t *testing.T) {
		jsonBytes := rebuild(base64.RawURLEncoding.EncodeToString(zBytes))
		k, err := jwk.ParseKey(jsonBytes)
		require.NoError(t, err, "raw URL must round-trip cleanly")
		v, ok := k.Field("z")
		require.True(t, ok, "z must be present after parse")
		zBack, ok := v.([]byte)
		require.True(t, ok, "z must be []byte after custom decoder")
		require.True(t, bytes.Equal(zBytes, zBack))
	})

	t.Run("URL with padding rejected", func(t *testing.T) {
		jsonBytes := rebuild(base64.URLEncoding.EncodeToString(zBytes))
		_, err := jwk.ParseKey(jsonBytes)
		require.Error(t, err, "padded URL form must be rejected")
		require.Contains(t, err.Error(), "base64url",
			"error must name the spec requirement")
	})

	t.Run("RawStd encoding rejected", func(t *testing.T) {
		// Use a value whose std and URL encodings differ — bytes that
		// produce '+' or '/' in std vs '-' or '_' in url. The
		// generated z is random; if it happens to use only the shared
		// alphabet, std and URL encodings coincide and the decoder
		// can't distinguish. Force a differing payload by setting one
		// known byte that lifts to '+' or '/' under std.
		differing := append([]byte{}, zBytes...)
		differing[0] = 0xfb // 0xfb__... begins with '+' under StdEncoding
		jsonBytes := rebuild(base64.RawStdEncoding.EncodeToString(differing))
		_, err := jwk.ParseKey(jsonBytes)
		require.Error(t, err, "raw std form must be rejected")
		require.Contains(t, err.Error(), "base64url")
	})

	t.Run("Std with padding rejected", func(t *testing.T) {
		differing := append([]byte{}, zBytes...)
		differing[0] = 0xfb
		jsonBytes := rebuild(base64.StdEncoding.EncodeToString(differing))
		_, err := jwk.ParseKey(jsonBytes)
		require.Error(t, err, "padded std form must be rejected")
		require.Contains(t, err.Error(), "base64url")
	})
}

func TestMalformedZFieldRejected(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	require.NoError(t, err)

	t.Run("wrong type", func(t *testing.T) {
		jkey, err := jwk.Import[jwk.Key](dk)
		require.NoError(t, err)
		require.NoError(t, jkey.Set("z", "not-bytes"))

		_, err = jwk.Export[*mlkem.DecapsulationKey768](jkey)
		require.Error(t, err)
		require.Contains(t, err.Error(), `"z" field is not []byte`)
	})

	t.Run("wrong length", func(t *testing.T) {
		jkey, err := jwk.Import[jwk.Key](dk)
		require.NoError(t, err)
		require.NoError(t, jkey.Set("z", []byte("short")))

		_, err = jwk.Export[*mlkem.DecapsulationKey768](jkey)
		require.Error(t, err)
		require.Contains(t, err.Error(), `"z" field must be 32 bytes`)
	})
}
