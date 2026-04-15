package mlkem

import "encoding/binary"

// deriveKey derives a key from the ML-KEM shared secret per
// draft-ietf-jose-pqc-kem-05 Section 5.1 ("Key Derivation for JOSE").
//
// The draft instantiates KMAC (NIST SP 800-108r1-upd1, built on KMAC256
// from NIST SP 800-185) with context fields from NIST SP 800-56Ar3
// Section 5.8.1:
//
//	SS = KMAC256(K=sharedSecret, X=AlgorithmID||SuppPubInfo, L=ssLen*8, S="")
//
// Section 5.1 of the draft delegates the encoding of AlgorithmID and
// SuppPubInfo to RFC 7518 Section 4.6.2: AlgorithmID is a length-prefixed
// octet string (big-endian 32-bit byte length, then the raw identifier
// bytes), and SuppPubInfo is the desired key length in bits encoded as a
// big-endian 32-bit unsigned integer. SuppPrivInfo and PartyUInfo are
// omitted — §5.1 explicitly drops PartyUInfo because KEMs do not
// authenticate the sender.
//
// alg is the algorithm identifier string — for direct mode, the "enc"
// (content encryption) algorithm; for key-wrap mode, the "alg" (key
// encryption) algorithm. ssLen is the desired output length in bytes.
//
// Interop caveat: draft-ietf-jose-pqc-kem is still at -05 and ships no
// KAT vectors or worked examples. The byte layout of X is pinned locally
// by kdf_test.go (derived from the spec chain above) but has not been
// cross-validated against a second conforming JOSE implementation,
// because no such implementation exists at the time of writing. Any
// future draft revision that tightens the AlgorithmID or SuppPubInfo
// encoding will break wire-level interop with messages produced here.
func deriveKey(sharedSecret []byte, alg string, ssLen int) []byte {
	algBytes := []byte(alg)

	// X = be32(len(alg)) || alg || be32(ssLen*8)
	x := make([]byte, 4+len(algBytes)+4)
	binary.BigEndian.PutUint32(x[0:4], uint32(len(algBytes)))
	copy(x[4:], algBytes)
	binary.BigEndian.PutUint32(x[4+len(algBytes):], uint32(ssLen)*8)

	return kmac256(sharedSecret, x, ssLen, "")
}
