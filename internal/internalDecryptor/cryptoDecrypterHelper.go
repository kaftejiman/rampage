package internaldecryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/pem"
	"fmt"
)

func ParsePrivateKey(bytes string) (*rsa.PrivateKey, error) {
	b, _ := b64.StdEncoding.DecodeString(bytes)
	pemBlock, _ := pem.Decode(b)
	if pemBlock == nil {
	}

	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		fmt.Println("error parsing private key", err)
	}

	return rsaPrivateKey, err
}

func decryptCBC(symmetricKey []byte, inBytes []byte, initializationVector []byte) ([]byte, error) {
	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, err
	}

	cfb := cipher.NewCBCDecrypter(block, initializationVector)
	cfb.CryptBlocks(inBytes, inBytes)
	return inBytes, nil
}
