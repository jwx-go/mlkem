package mlkem

import (
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

// kmac256 computes KMAC256(K, X, L, S) per NIST SP 800-185 Section 4.
//
//	K: key
//	x: input data
//	outputLen: desired output length in bytes
//	s: customization string
func kmac256(key, x []byte, outputLen int, s string) []byte {
	h := sha3.NewCShake256([]byte("KMAC"), []byte(s))

	writeBytepad(h, key, 136)
	_, _ = h.Write(x)
	_, _ = h.Write(rightEncode(uint64(outputLen) * 8))

	out := make([]byte, outputLen)
	_, _ = h.Read(out)
	return out
}

// writeBytepad writes bytepad(encode_string(K), w) to h.
func writeBytepad(h sha3.ShakeHash, x []byte, w int) {
	lew := leftEncode(uint64(w))
	_, _ = h.Write(lew)

	les := leftEncode(uint64(len(x)) * 8)
	_, _ = h.Write(les)
	_, _ = h.Write(x)

	written := len(lew) + len(les) + len(x)
	padLen := w - (written % w)
	if padLen < w {
		zeros := make([]byte, padLen)
		_, _ = h.Write(zeros)
	}
}

// leftEncode encodes x as left_encode(x) per NIST SP 800-185.
func leftEncode(x uint64) []byte {
	if x == 0 {
		return []byte{1, 0}
	}
	var buf [9]byte
	binary.BigEndian.PutUint64(buf[1:], x)

	i := 1
	for i < 9 && buf[i] == 0 {
		i++
	}

	n := byte(9 - i)
	buf[i-1] = n
	return buf[i-1:]
}

// rightEncode encodes x as right_encode(x) per NIST SP 800-185.
func rightEncode(x uint64) []byte {
	if x == 0 {
		return []byte{0, 1}
	}
	var buf [9]byte
	binary.BigEndian.PutUint64(buf[:8], x)

	i := 0
	for i < 8 && buf[i] == 0 {
		i++
	}

	n := byte(8 - i)
	buf[8] = n
	return buf[i:]
}
