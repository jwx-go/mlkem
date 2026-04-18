package mlkem_test

import (
	"crypto/mlkem"
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
		sealed, kemCT, err := enc.EncryptMLKEM(cek, "ML-KEM-768", "A256GCM")
		require.NoError(t, err)
		_, err = dec.DecryptMLKEM(sealed, "ML-KEM-768", "A256GCM", kemCT)
		require.NoError(t, err)
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
