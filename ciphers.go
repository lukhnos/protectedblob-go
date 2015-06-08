package protectedblob // import "lukhnos.org/protectedblob"

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
)

var _ = os.Stdout
var _ = fmt.Println

type CipherSuite interface {
	Name() string
	Validate(src Data) error
	GenerateKey() ([]byte, error)
	checkHMAC(key []byte, data Data) error
	Decrypt(key []byte, data Data) ([]byte, error)
	Encrypt(key, plaintext []byte) (Data, error)
}

func hmacError() error {
	return &BlobError{"Incorrect decryption key"}
}

type _AES256CBCSHA256 struct {
}

var AES256CBCSHA256 = _AES256CBCSHA256{}

func padPKCS7(msg []byte, blockSize int) []byte {
	paddingLen := blockSize - len(msg)%blockSize
	paddedMsg := make([]byte, len(msg)+paddingLen)
	copy(paddedMsg, msg)
	copy(paddedMsg[len(msg):], bytes.Repeat([]byte{byte(paddingLen)}, paddingLen))
	return paddedMsg
}

func unpadPKCS7(msg []byte) []byte {
	padLen := msg[len(msg)-1]
	return msg[:len(msg)-int(padLen)]
}

func (suite _AES256CBCSHA256) deriveKeys(src []byte) DerivedKeyPair {
	block, _ := aes.NewCipher(src)
	kp := DerivedKeyPair{CipherKey: make([]byte, 32), HMACKey: make([]byte, 32)}
	block.Encrypt(kp.CipherKey[0:16], bytes.Repeat([]byte{0}, aes.BlockSize))
	block.Encrypt(kp.CipherKey[16:32], bytes.Repeat([]byte{1}, aes.BlockSize))
	block.Encrypt(kp.HMACKey[0:16], bytes.Repeat([]byte{2}, aes.BlockSize))
	block.Encrypt(kp.HMACKey[16:32], bytes.Repeat([]byte{3}, aes.BlockSize))
	return kp
}

func (suite _AES256CBCSHA256) Name() string {
	return "AES256-CBC-SHA256"
}

func (suite _AES256CBCSHA256) Validate(src Data) error {
	if len(src.IV) != aes.BlockSize {
		return blobError("Invalid IV")
	}

	if ctLength := len(src.Ciphertext); ctLength < aes.BlockSize || ctLength%aes.BlockSize != 0 {
		return blobError("Invalid ciphertext length")
	}

	if len(src.HMAC) != 32 {
		return blobError("Invalid HMAC")
	}

	return nil
}

func (suite _AES256CBCSHA256) GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func (suite _AES256CBCSHA256) checkHMAC(key []byte, data Data) error {
	kp := suite.deriveKeys(key)

	mac := hmac.New(sha256.New, kp.HMACKey)
	mac.Write(data.Ciphertext)
	if !hmac.Equal(mac.Sum(nil), data.HMAC) {
		return hmacError()
	}

	return nil
}

func (suite _AES256CBCSHA256) Decrypt(key []byte, data Data) ([]byte, error) {
	kp := suite.deriveKeys(key)

	mac := hmac.New(sha256.New, kp.HMACKey)
	mac.Write(data.Ciphertext)
	if !hmac.Equal(mac.Sum(nil), data.HMAC) {
		return nil, hmacError()
	}

	paddedPlaintext := make([]byte, len(data.Ciphertext))
	block, err := aes.NewCipher(kp.CipherKey)
	if err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCDecrypter(block, data.IV)
	cbc.CryptBlocks(paddedPlaintext, data.Ciphertext)
	return unpadPKCS7(paddedPlaintext), nil
}

func (suite _AES256CBCSHA256) Encrypt(key, plaintext []byte) (Data, error) {
	kp := suite.deriveKeys(key)

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return Data{}, err
	}

	block, err := aes.NewCipher(kp.CipherKey)
	if err != nil {
		return Data{}, nil
	}

	paddedMsg := padPKCS7(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(paddedMsg))
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext, paddedMsg)

	mac := hmac.New(sha256.New, kp.HMACKey)
	mac.Write(ciphertext)

	return Data{IV: iv, Ciphertext: ciphertext, HMAC: mac.Sum(nil)}, nil
}
