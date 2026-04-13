package mlkem

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// Test vectors from NIST SP 800-185 Section A.4 (KMAC samples).
func TestKMAC256(t *testing.T) {
	t.Run("SP800-185 Sample #4", func(t *testing.T) {
		key, _ := hex.DecodeString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")
		x, _ := hex.DecodeString("00010203")
		s := "My Tagged Application"
		expected, _ := hex.DecodeString(
			"20C570C31346F703C9AC36C61C03CB64" +
				"C3970D0CFC787E9B79599D273A68D2F7" +
				"F69D4CC3DE9D104A351689F27CF6F595" +
				"1F0103F33F4F24871024D9C27773A8DD",
		)

		got := kmac256(key, x, 64, s)
		require.Equal(t, expected, got)
	})

	t.Run("SP800-185 Sample #5", func(t *testing.T) {
		key, _ := hex.DecodeString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")
		x := make([]byte, 200)
		for i := range x {
			x[i] = byte(i)
		}
		expected, _ := hex.DecodeString(
			"75358CF39E41494E949707927CEE0AF2" +
				"0A3FF553904C86B08F21CC414BCFD691" +
				"589D27CF5E15369CBBFF8B9A4C2EB178" +
				"00855D0235FF635DA82533EC6B759B69",
		)

		got := kmac256(key, x, 64, "")
		require.Equal(t, expected, got)
	})
}

func TestLeftEncode(t *testing.T) {
	require.Equal(t, []byte{1, 0}, leftEncode(0))
	require.Equal(t, []byte{1, 1}, leftEncode(1))
	require.Equal(t, []byte{1, 255}, leftEncode(255))
	require.Equal(t, []byte{2, 1, 0}, leftEncode(256))
}

func TestRightEncode(t *testing.T) {
	require.Equal(t, []byte{0, 1}, rightEncode(0))
	require.Equal(t, []byte{1, 1}, rightEncode(1))
	require.Equal(t, []byte{255, 1}, rightEncode(255))
	require.Equal(t, []byte{1, 0, 2}, rightEncode(256))
}
