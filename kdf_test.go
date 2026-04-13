package mlkem

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDeriveKeyAlgorithmIDPrefix verifies that the KDF input X is
// constructed as
//
//	X = be32(len(alg)) || alg || be32(ssLen*8)
//
// per RFC 7518 Section 4.6.2 (AlgorithmID encoded as a length-prefixed
// octet string). The previous implementation omitted the 4-byte length
// prefix and concatenated the raw alg bytes directly, producing output
// that diverges from the spec format and cannot interoperate with any
// other implementation.
//
// The expected bytes are derived by running kmac256 — independently
// validated by TestKMAC256 against NIST SP 800-185 vectors — against
// the spec-correct X buffer constructed inline below. If the production
// deriveKey constructs X differently, its output will not match, and
// this test will fail.
func TestDeriveKeyAlgorithmIDPrefix(t *testing.T) {
	cases := []struct {
		name  string
		alg   string
		ssLen int
	}{
		{name: "A256GCM-32", alg: "A256GCM", ssLen: 32},
		{name: "A256KW-32", alg: "A256KW", ssLen: 32},
		{name: "A128CBC-HS256-32", alg: "A128CBC-HS256", ssLen: 32},
		{name: "A192CBC-HS384-48", alg: "A192CBC-HS384", ssLen: 48},
		{name: "A256CBC-HS512-64", alg: "A256CBC-HS512", ssLen: 64},
	}

	// 32 bytes — represents an ML-KEM-768 shared secret length.
	sharedSecret := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			algBytes := []byte(tc.alg)

			// Spec-correct X per RFC 7518 §4.6.2:
			//   AlgorithmID = be32(len(alg)) || alg
			//   SuppPubInfo = be32(ssLen*8)
			//   X = AlgorithmID || SuppPubInfo
			x := make([]byte, 4+len(algBytes)+4)
			binary.BigEndian.PutUint32(x[0:4], uint32(len(algBytes)))
			copy(x[4:], algBytes)
			binary.BigEndian.PutUint32(x[4+len(algBytes):], uint32(tc.ssLen)*8)

			expected := kmac256(sharedSecret, x, tc.ssLen, "")
			actual := deriveKey(sharedSecret, tc.alg, tc.ssLen)

			require.Equal(t, expected, actual,
				`deriveKey output must match kmac256 over spec-correct X (be32(len(alg))||alg||be32(ssLen*8))`)
		})
	}
}

// TestDeriveKeyOutputLength is a sanity check that deriveKey returns
// exactly ssLen bytes. This guards against any future change that
// silently truncates or pads the KMAC output.
func TestDeriveKeyOutputLength(t *testing.T) {
	for _, ssLen := range []int{16, 24, 32, 48, 64} {
		out := deriveKey([]byte("shared"), "A256GCM", ssLen)
		require.Len(t, out, ssLen, `deriveKey must return exactly ssLen bytes`)
	}
}
