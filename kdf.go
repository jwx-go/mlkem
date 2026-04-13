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
// alg is the algorithm identifier string — for direct mode, the "enc"
// (content encryption) algorithm; for key-wrap mode, the "alg" (key
// encryption) algorithm. ssLen is the desired output length in bytes.
func deriveKey(sharedSecret []byte, alg string, ssLen int) []byte {
	algBytes := []byte(alg)
	var suppPubInfo [4]byte
	binary.BigEndian.PutUint32(suppPubInfo[:], uint32(ssLen)*8)

	x := make([]byte, len(algBytes)+4)
	copy(x, algBytes)
	copy(x[len(algBytes):], suppPubInfo[:])

	return kmac256(sharedSecret, x, ssLen, "")
}
