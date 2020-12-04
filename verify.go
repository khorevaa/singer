package singer

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
)

type Singer interface {
	Sing(data []byte) (sig []byte, err error)
}

func Sing(data []byte, s Singer) (sig []byte, err error) {
	return s.Sing(data)
}

func Verify(publicKey *rsa.PublicKey, data []byte, sig []byte) error {

	hashed := sha256.Sum256(data)

	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], sig); err != nil {
		return err
	}
	return nil
}
