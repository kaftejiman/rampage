package internalencryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/pem"
	"fmt"
)

func ParsePublicKey(bytes string) (*rsa.PublicKey, error) {
	b, _ := b64.StdEncoding.DecodeString(bytes)
	pemBlock, _ := pem.Decode(b)
	if pemBlock == nil {
	}

	rsaPublicKey, err := x509.ParsePKCS1PublicKey(pemBlock.Bytes)
	if err != nil {
		fmt.Println("error parsing public key", err)
	}
	return rsaPublicKey, err

}

func encryptCBC(symmetricKey []byte, inBytes []byte, initializationVector []byte) ([]byte, error) {
	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, err
	}

	inBytesLen := len(inBytes)
	if inBytesLen%aes.BlockSize != 0 {
		return nil, err
	}
	ciphertext := make([]byte, inBytesLen)
	cfb := cipher.NewCBCEncrypter(block, initializationVector)
	cfb.CryptBlocks(ciphertext, inBytes)

	return ciphertext, nil
}
