package mlkem_test

import (
	"bytes"
	"crypto/mlkem"
	"encoding/json"
	"testing"

	jwxmlkem "github.com/jwx-go/mlkem/v4"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

func FuzzEncryptDecryptMLKEM768(f *testing.F) {
	f.Add([]byte("Hello, post-quantum world!"))
	f.Add([]byte(""))
	f.Add([]byte(`{"iss":"test"}`))

	dk, err := mlkem.GenerateKey768()
	if err != nil {
		f.Fatal(err)
	}
	ek := dk.EncapsulationKey()

	f.Fuzz(func(t *testing.T, payload []byte) {
		encrypted, err := jwe.Encrypt(payload,
			jwe.WithKey(jwxmlkem.MLKEM768(), ek),
			jwe.WithContentEncryption(jwa.A256GCM()),
		)
		require.NoError(t, err)

		decrypted, err := jwe.Decrypt(encrypted,
			jwe.WithKey(jwxmlkem.MLKEM768(), dk),
		)
		require.NoError(t, err)
		require.True(t, bytes.Equal(payload, decrypted))
	})
}

func FuzzEncryptDecryptMLKEM1024(f *testing.F) {
	f.Add([]byte("Hello, post-quantum world!"))
	f.Add([]byte(""))
	f.Add([]byte(`{"iss":"test"}`))

	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		f.Fatal(err)
	}
	ek := dk.EncapsulationKey()

	f.Fuzz(func(t *testing.T, payload []byte) {
		encrypted, err := jwe.Encrypt(payload,
			jwe.WithKey(jwxmlkem.MLKEM1024(), ek),
			jwe.WithContentEncryption(jwa.A256GCM()),
		)
		require.NoError(t, err)

		decrypted, err := jwe.Decrypt(encrypted,
			jwe.WithKey(jwxmlkem.MLKEM1024(), dk),
		)
		require.NoError(t, err)
		require.True(t, bytes.Equal(payload, decrypted))
	})
}

func FuzzEncryptDecryptMLKEM768A192KW(f *testing.F) {
	f.Add([]byte("Hello, post-quantum world!"))
	f.Add([]byte(""))
	f.Add([]byte(`{"iss":"test"}`))

	dk, err := mlkem.GenerateKey768()
	if err != nil {
		f.Fatal(err)
	}
	ek := dk.EncapsulationKey()

	f.Fuzz(func(t *testing.T, payload []byte) {
		encrypted, err := jwe.Encrypt(payload,
			jwe.WithKey(jwxmlkem.MLKEM768A192KW(), ek),
			jwe.WithContentEncryption(jwa.A256GCM()),
		)
		require.NoError(t, err)

		decrypted, err := jwe.Decrypt(encrypted,
			jwe.WithKey(jwxmlkem.MLKEM768A192KW(), dk),
		)
		require.NoError(t, err)
		require.True(t, bytes.Equal(payload, decrypted))
	})
}

func FuzzEncryptDecryptMLKEM1024A256KW(f *testing.F) {
	f.Add([]byte("Hello, post-quantum world!"))
	f.Add([]byte(""))
	f.Add([]byte(`{"iss":"test"}`))

	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		f.Fatal(err)
	}
	ek := dk.EncapsulationKey()

	f.Fuzz(func(t *testing.T, payload []byte) {
		encrypted, err := jwe.Encrypt(payload,
			jwe.WithKey(jwxmlkem.MLKEM1024A256KW(), ek),
			jwe.WithContentEncryption(jwa.A256GCM()),
		)
		require.NoError(t, err)

		decrypted, err := jwe.Decrypt(encrypted,
			jwe.WithKey(jwxmlkem.MLKEM1024A256KW(), dk),
		)
		require.NoError(t, err)
		require.True(t, bytes.Equal(payload, decrypted))
	})
}

func FuzzJWKRoundTrip(f *testing.F) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		f.Fatal(err)
	}
	jwkKey, err := jwk.Import[jwk.Key](dk)
	if err != nil {
		f.Fatal(err)
	}
	seedJSON, err := json.Marshal(jwkKey)
	if err != nil {
		f.Fatal(err)
	}

	f.Add(seedJSON)
	f.Add([]byte(""))
	f.Add([]byte("not-json"))
	f.Add([]byte(`{"kty":"AKP","alg":"ML-KEM-768","pub":"AAAA"}`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		parsed, err := jwk.ParseKeyAs[jwk.Key](data)
		if err != nil {
			return
		}

		buf, err := json.Marshal(parsed)
		if err != nil {
			return
		}

		_, _ = jwk.ParseKeyAs[jwk.Key](buf)
	})
}
