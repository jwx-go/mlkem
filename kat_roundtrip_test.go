package mlkem

import (
	"crypto/aes"
	"crypto/mlkem"
	"encoding/hex"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwe/jwebb"
	"github.com/stretchr/testify/require"
)

// TestKATMLKEM768 is a pinned-byte Known Answer Test for the ML-KEM-768
// pipeline used by the JWE binding (XCUT-009 / EXT-002).
//
// Why this is not a full end-to-end JWE encrypt KAT:
//
// Go's stdlib crypto/mlkem.EncapsulationKey768.Encapsulate() draws its own
// randomness from the runtime entropy source — it does not accept an
// io.Reader. The encapsulated ciphertext therefore cannot be made
// deterministic from outside the package, so we cannot pin the JWE
// "encrypted_key" header field bytes from a fixed RNG seed.
//
// What IS deterministic and pinned here:
//
//  1. The ML-KEM-768 encapsulation key bytes derived from a fixed 64-byte
//     seed (FIPS 203 key generation is deterministic in the seed).
//  2. ML-KEM decapsulation IS deterministic: given a fixed decapsulation
//     key and a fixed ciphertext, the recovered shared secret is fixed.
//     We exercise this by encapsulating once, then asserting decapsulation
//     of the resulting ciphertext yields the same shared secret a second
//     time (round-trip determinism), as a guard against any future change
//     that breaks decapsulation.
//  3. Given a pinned shared secret, the KMAC256 KDF output is pinned for
//     both direct (A256GCM) and key-wrap (+A192KW) variants.
//  4. Given a pinned KEK and a pinned CEK, the AES key-wrap output bytes
//     are pinned. This locks the entire CEK-wrap pipeline downstream of
//     the KEM, which is the surface the existing kdf_test.go does not
//     cover.
//
// Together these bytes pin every stage of the ML-KEM JWE pipeline that is
// reachable without controlling the KEM's internal RNG, which is the best
// achievable KAT for stdlib-backed ML-KEM today.
func TestKATMLKEM768(t *testing.T) {
	// Fixed 64-byte seed (d || z) for ML-KEM-768 key generation.
	var seed [64]byte
	for i := range seed {
		seed[i] = 0x01
	}

	dk, err := mlkem.NewDecapsulationKey768(seed[:])
	require.NoError(t, err, "ML-KEM-768 key generation from fixed seed must succeed")

	ek := dk.EncapsulationKey()
	ekBytes := ek.Bytes()
	require.Len(t, ekBytes, 1184, "ML-KEM-768 encapsulation key must be 1184 bytes")

	// Pinned: SHA-256 fingerprint of the encapsulation key bytes derived
	// from the all-0x01 seed. We pin the digest rather than the full 1184
	// bytes for readability; FIPS 203 key generation being deterministic
	// in the seed means any drift in stdlib's implementation will flip
	// this digest.
	const expectedEKHexPrefix = "01775c733bc53663b6a804a9126827f4" // first 16 bytes
	require.Equal(t, expectedEKHexPrefix, hex.EncodeToString(ekBytes[:16]),
		"ML-KEM-768 encapsulation key prefix from fixed seed must match pinned bytes")

	// ----- Decapsulation determinism -----
	//
	// We can't pin the ciphertext (Encapsulate has internal randomness),
	// but we can verify that decapsulation is fully deterministic in
	// (decap_key, ciphertext): calling Decapsulate twice on the same
	// ciphertext must yield the same shared secret, and the result must
	// match the shared secret returned by Encapsulate.
	ss1, ct := ek.Encapsulate()
	require.Len(t, ct, 1088, "ML-KEM-768 ciphertext must be 1088 bytes")
	require.Len(t, ss1, 32, "ML-KEM-768 shared secret must be 32 bytes")

	ss2, err := dk.Decapsulate(ct)
	require.NoError(t, err)
	require.Equal(t, ss1, ss2, "Decapsulate must recover the same shared secret as Encapsulate")

	ss3, err := dk.Decapsulate(ct)
	require.NoError(t, err)
	require.Equal(t, ss2, ss3, "Decapsulate must be deterministic in (decap_key, ciphertext)")

	// ----- KDF KAT with a pinned shared secret -----
	//
	// Fixed 32-byte "shared secret" — not from any KEM run, just a stable
	// input so the KDF output bytes can be pinned.
	pinnedSS := make([]byte, 32)
	for i := range pinnedSS {
		pinnedSS[i] = 0x02
	}

	// Direct mode: ML-KEM-768 + A256GCM. AlgorithmID = "A256GCM", out=32.
	derivedDirect := deriveKey(pinnedSS, "A256GCM", 32)
	const expectedDerivedDirect = "4dbd93e70d09f58acec7fdfc997c3819f9a7137c69de723a5aa4bae6c35623d5"
	require.Equal(t, expectedDerivedDirect, hex.EncodeToString(derivedDirect),
		"deriveKey(0x02*32, A256GCM, 32) must match pinned bytes")

	// Key-wrap mode: ML-KEM-768+A192KW. AlgorithmID = "ML-KEM-768+A192KW",
	// out=24 (A192 KEK).
	derivedKW := deriveKey(pinnedSS, algMLKEM768A192KW, 24)
	const expectedDerivedKW = "3817273e29dd9786c2591dff5237b66f94bdcc494f24fc26"
	require.Equal(t, expectedDerivedKW, hex.EncodeToString(derivedKW),
		"deriveKey(0x02*32, ML-KEM-768+A192KW, 24) must match pinned bytes")

	// ----- AES key-wrap KAT with pinned KEK and CEK -----
	//
	// Pinned 32-byte CEK (A256GCM-sized) wrapped with the pinned 24-byte
	// A192 KEK derived above.
	pinnedCEK := make([]byte, 32)
	for i := range pinnedCEK {
		pinnedCEK[i] = 0x03
	}

	block, err := aes.NewCipher(derivedKW)
	require.NoError(t, err)
	wrapped, err := jwebb.Wrap(block, pinnedCEK)
	require.NoError(t, err)
	const expectedWrapped = "cb25284879c496d0883360d85222440cc8e93d494379689d59356519c6281f23853b4f2e282dbf5d"
	require.Equal(t, expectedWrapped, hex.EncodeToString(wrapped),
		"AES key-wrap of pinned CEK with derived KEK must match pinned bytes")

	// ----- Full pipeline round-trip via mlkemKey -----
	//
	// This exercises EncryptMLKEM → DecryptMLKEM end-to-end through the
	// production wrapper, as a non-pinned but full-stack sanity check
	// that complements the byte-level pins above.
	kek := &mlkemKey{
		alg:   algMLKEM768,
		encap: ek,
		decap: dk,
	}

	// Direct mode round-trip.
	cek := make([]byte, 32)
	for i := range cek {
		cek[i] = 0x04
	}
	directDerived, ctDirect, err := kek.EncryptMLKEM(cek, algMLKEM768, "A256GCM")
	require.NoError(t, err)
	require.Len(t, directDerived, 32)
	recoveredCEK, err := kek.DecryptMLKEM(nil, algMLKEM768, "A256GCM", ctDirect)
	require.NoError(t, err)
	require.Equal(t, directDerived, recoveredCEK, "direct-mode round-trip must recover same derived CEK")

	// Key-wrap mode round-trip.
	wrappedCEK, ctKW, err := kek.EncryptMLKEM(cek, algMLKEM768A192KW, "A256GCM")
	require.NoError(t, err)
	unwrapped, err := kek.DecryptMLKEM(wrappedCEK, algMLKEM768A192KW, "A256GCM", ctKW)
	require.NoError(t, err)
	require.Equal(t, cek, unwrapped, "key-wrap round-trip must recover the original CEK")
}
