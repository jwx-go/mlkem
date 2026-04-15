package mlkem

import (
	"crypto/aes"
	"crypto/mlkem"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwe/jwebb"
)

// DecryptMLKEM implements jwebb.MLKEMKeyDecrypter.
func (k *mlkemKey) DecryptMLKEM(sealedCEK []byte, alg, calg string, enc []byte) ([]byte, error) {
	if want := bareAlg(alg); k.alg != "" && want != k.alg {
		return nil, fmt.Errorf(`mlkem: alg %q does not match key variant %q`, alg, k.alg)
	}
	sharedSecret, err := k.decapsulate(enc)
	if err != nil {
		return nil, err
	}

	keysize, err := derivedKeySize(alg, calg)
	if err != nil {
		return nil, err
	}
	derived := deriveKey(sharedSecret, kdfAlgorithmID(alg, calg), keysize)

	if isDirectAlg(alg) {
		// Direct: derived is the CEK; sealedCEK is unused.
		return derived, nil
	}

	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, fmt.Errorf(`mlkem: failed to create AES cipher from ML-KEM derived KEK: %w`, err)
	}
	return jwebb.Unwrap(block, sealedCEK)
}

func (k *mlkemKey) decapsulate(ciphertext []byte) ([]byte, error) {
	switch dk := k.decap.(type) {
	case *mlkem.DecapsulationKey768:
		return dk.Decapsulate(ciphertext)
	case *mlkem.DecapsulationKey1024:
		return dk.Decapsulate(ciphertext)
	default:
		return nil, fmt.Errorf(`mlkem: decapsulation key not present (private key required)`)
	}
}
