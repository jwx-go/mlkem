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
		// Direct: derived is the CEK itself.
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
