package mlkem

import (
	"crypto/aes"
	"crypto/mlkem"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwe/jwebb"
)

// mlkemKey wraps an ML-KEM key pair (encapsulation key always present;
// decapsulation key present only when sourced from a private JWK or raw
// decapsulation key). It implements both jwebb.MLKEMKeyEncrypter and
// jwebb.MLKEMKeyDecrypter — the decrypter methods return an error when
// no private component is available.
type mlkemKey struct {
	alg   string // "ML-KEM-768" or "ML-KEM-1024"
	encap any    // *mlkem.EncapsulationKey768 or *mlkem.EncapsulationKey1024
	decap any    // *mlkem.DecapsulationKey768 or *mlkem.DecapsulationKey1024 (nil for public-only)
}

var (
	_ jwebb.MLKEMKeyEncrypter = (*mlkemKey)(nil)
	_ jwebb.MLKEMKeyDecrypter = (*mlkemKey)(nil)
)

// EncryptMLKEM implements jwebb.MLKEMKeyEncrypter.
//
// In direct mode (alg == "ML-KEM-768" or "ML-KEM-1024"), the supplied
// cek argument is intentionally ignored: per draft-ietf-jose-pqc-kem,
// the KEM-derived bytes are themselves the CEK and are returned as
// the first value. The returned sealedCEK in direct mode is the bare
// derived key, not an AES-KW envelope around the supplied cek. Callers
// implementing MLKEMKeyEncrypter for an external key store should
// follow the same semantics so jwx core's content-encryption step
// uses the right CEK.
//
// In key-wrap mode (alg == "ML-KEM-{768,1024}+A{192,256}KW"), the
// supplied cek is wrapped under the AES-KW key derived from the KEM
// shared secret, and the returned first value is the wrapped CEK.
func (k *mlkemKey) EncryptMLKEM(cek []byte, alg, calg string) ([]byte, []byte, error) {
	if want := bareAlg(alg); k.alg != "" && want != k.alg {
		return nil, nil, fmt.Errorf(`mlkem: alg %q does not match key variant %q`, alg, k.alg)
	}
	sharedSecret, ciphertext, err := k.encapsulate()
	if err != nil {
		return nil, nil, err
	}

	keysize, err := derivedKeySize(alg, calg)
	if err != nil {
		return nil, nil, err
	}
	derived := deriveKey(sharedSecret, kdfAlgorithmID(alg, calg), keysize)

	if isDirectAlg(alg) {
		// Direct: derived is the CEK itself; cek argument is ignored
		// (see godoc on EncryptMLKEM).
		return derived, ciphertext, nil
	}

	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, nil, fmt.Errorf(`mlkem: failed to create AES cipher from ML-KEM derived KEK: %w`, err)
	}
	wrapped, err := jwebb.Wrap(block, cek)
	if err != nil {
		return nil, nil, fmt.Errorf(`mlkem: failed to wrap CEK: %w`, err)
	}
	return wrapped, ciphertext, nil
}

func (k *mlkemKey) encapsulate() (sharedSecret, ciphertext []byte, err error) {
	switch ek := k.encap.(type) {
	case *mlkem.EncapsulationKey768:
		ss, ct := ek.Encapsulate()
		return ss, ct, nil
	case *mlkem.EncapsulationKey1024:
		ss, ct := ek.Encapsulate()
		return ss, ct, nil
	default:
		return nil, nil, fmt.Errorf(`mlkem: encapsulation key not present`)
	}
}
