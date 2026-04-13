package mlkem

import "encoding/binary"

// deriveKey derives a key from the ML-KEM shared secret per
// draft-ietf-jose-pqc-kem.
//
// The KDF uses KMAC256 per NIST SP 800-185 with context fields from
// NIST SP 800-56Ar3 Section 5.8.1:
//
//	SS = KMAC256(K=sharedSecret, X=AlgorithmID||SuppPubInfo, L=ssLen*8, S="")
//
// AlgorithmID is encoded per RFC 7518 Section 4.6.2 as a length-prefixed
// octet string: a big-endian 32-bit byte length followed by the raw
// bytes of the algorithm identifier. SuppPubInfo is the desired key
// length in bits, encoded as a big-endian 32-bit unsigned integer.
//
// alg is the algorithm identifier string — for direct mode, the "enc"
// (content encryption) algorithm; for key-wrap mode, the "alg" (key
// encryption) algorithm. ssLen is the desired output length in bytes.
func deriveKey(sharedSecret []byte, alg string, ssLen int) []byte {
	algBytes := []byte(alg)

	// X = be32(len(alg)) || alg || be32(ssLen*8)
	x := make([]byte, 4+len(algBytes)+4)
	binary.BigEndian.PutUint32(x[0:4], uint32(len(algBytes)))
	copy(x[4:], algBytes)
	binary.BigEndian.PutUint32(x[4+len(algBytes):], uint32(ssLen)*8)

	return kmac256(sharedSecret, x, ssLen, "")
}
