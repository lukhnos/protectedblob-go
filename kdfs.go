package protectedblob // import "lukhnos.org/protectedblob"

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"golang.org/x/crypto/pbkdf2"
)

type KDF interface {
	Name() string
	Validate(src ProtectedKey) error
	Encrypt(key []byte, passphrase string, rounds int32) (ProtectedKey, error)
	Decrypt(src ProtectedKey, passphrase string) ([]byte, error)
}

type _PBKDF2SHA256AES256 struct {
}

var PBKDF2SHA256AES256 = _PBKDF2SHA256AES256{}

func (kdf _PBKDF2SHA256AES256) Name() string {
	return "PBKDF2-SHA256-AES256"
}

func (kdf _PBKDF2SHA256AES256) Validate(src ProtectedKey) error {
	if len(src.Salt) != sha256.Size {
		return blobError("Invalid Salt")
	}

	if src.Rounds < 1 {
		return blobError("Invalid Rounds")
	}

	if len(src.EncryptedKey) != 32 {
		return blobError("Invalid EncryptedKey")
	}

	return nil
}

func (kdf _PBKDF2SHA256AES256) Decrypt(src ProtectedKey, passphrase string) ([]byte, error) {
	key := pbkdf2.Key([]byte(passphrase), src.Salt, int(src.Rounds), 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	decryptedKey := make([]byte, aes.BlockSize*2)
	block.Decrypt(decryptedKey[:aes.BlockSize], src.EncryptedKey[:aes.BlockSize])
	block.Decrypt(decryptedKey[aes.BlockSize:], src.EncryptedKey[aes.BlockSize:])
	return decryptedKey, nil
}

func (kdf _PBKDF2SHA256AES256) Encrypt(key []byte, passphrase string, rounds int32) (ProtectedKey, error) {
	if len(key) != 32 {
		return ProtectedKey{}, blobError("Invalid key size")
	}

	if rounds < 1 {
		return ProtectedKey{}, blobError("Invalid Rounds")
	}

	salt := make([]byte, sha256.Size)
	if _, err := rand.Read(salt); err != nil {
		return ProtectedKey{}, err
	}

	encryptionKey := pbkdf2.Key([]byte(passphrase), salt, int(rounds), 32, sha256.New)
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return ProtectedKey{}, err
	}

	encryptedKey := make([]byte, 32)
	block.Encrypt(encryptedKey[:aes.BlockSize], key[:aes.BlockSize])
	block.Encrypt(encryptedKey[aes.BlockSize:], key[aes.BlockSize:])
	return ProtectedKey{Salt: salt, Rounds: rounds, EncryptedKey: encryptedKey}, nil
}
