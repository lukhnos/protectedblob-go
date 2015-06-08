package protectedblob

import (
	"encoding/json"
)

const DefaultRounds int32 = 131072
const SupportedVersion string = "2"

var defaultKDF = PBKDF2SHA256AES256
var defaultCipherSuite = AES256CBCSHA256

type ProtectedKey struct {
	Salt         []byte `json:"salt"`
	Rounds       int32  `json:"rounds"`
	EncryptedKey []byte `json:"encrypted_key"`
}

type DerivedKeyPair struct {
	CipherKey []byte
	HMACKey   []byte
}

type Data struct {
	IV         []byte `json:"iv"`
	Ciphertext []byte `json:"ciphertext"`
	HMAC       []byte `json:"hmac"`
}

type Envelope struct {
	Version      string       `json:"version"`
	CipherSuite  string       `json:"cipher_suite"`
	KDF          string       `json:"kdf"`
	Data         Data         `json:"encrypted_data"`
	ProtectedKey ProtectedKey `json:"encrypted_key"`
}

type BlobError struct {
	s string
}

func (e *BlobError) Error() string {
	return e.s
}

func blobError(text string) error {
	return &BlobError{text}
}

func (envlp *Envelope) validate() error {
	if envlp.Version != SupportedVersion {
		return blobError("Unsupported version")
	}

	kdf := envlp.getKDF()
	if kdf == nil {
		return blobError("Unsupported KDF")
	}

	if err := kdf.Validate(envlp.ProtectedKey); err != nil {
		return err
	}

	cipherSuite := envlp.getCipherSuite()
	if cipherSuite == nil {
		return blobError("Unsupported cipher suite")
	}

	if err := cipherSuite.Validate(envlp.Data); err != nil {
		return err
	}

	return nil
}

func (envlp *Envelope) getKDF() KDF {
	if envlp.KDF == PBKDF2SHA256AES256.Name() {
		return PBKDF2SHA256AES256
	}

	return nil
}

func (envlp *Envelope) getCipherSuite() CipherSuite {
	if envlp.CipherSuite == AES256CBCSHA256.Name() {
		return AES256CBCSHA256
	}

	return nil
}

func FromJSON(data []byte) (Envelope, error) {
	var envlp Envelope
	err := json.Unmarshal(data, &envlp)
	if err != nil {
		return Envelope{}, err
	}

	if err := envlp.validate(); err != nil {
		return Envelope{}, err
	}

	return envlp, nil
}

func (envlp *Envelope) ToJSON() ([]byte, error) {
	return json.Marshal(envlp)
}

func (envlp *Envelope) GetPlaintext(passphrase string) ([]byte, error) {
	if err := envlp.validate(); err != nil {
		return nil, err
	}

	kdf := envlp.getKDF()
	cipherSuite := envlp.getCipherSuite()

	key, err := kdf.Decrypt(envlp.ProtectedKey, passphrase)
	if err != nil {
		return nil, err
	}

	plaintext, err := cipherSuite.Decrypt(key, envlp.Data)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func Create(plaintext []byte, passphrase string, rounds int32) (Envelope, error) {
	kdf := defaultKDF
	cipherSuite := defaultCipherSuite

	key, err := cipherSuite.GenerateKey()
	if err != nil {
		return Envelope{}, err
	}

	protectedKey, err := kdf.Encrypt(key, passphrase, rounds)
	if err != nil {
		return Envelope{}, err
	}

	data, err := cipherSuite.Encrypt(key, plaintext)
	if err != nil {
		return Envelope{}, err
	}

	envelope := Envelope{
		Version:      SupportedVersion,
		CipherSuite:  cipherSuite.Name(),
		KDF:          kdf.Name(),
		Data:         data,
		ProtectedKey: protectedKey}
	return envelope, nil
}

func (envlp *Envelope) ChangePassphrase(oldPhrase string, newPhrase string) error {
	return envlp.ChangePassphraseAndRounds(oldPhrase, newPhrase, envlp.ProtectedKey.Rounds)
}

func (envlp *Envelope) ChangePassphraseAndRounds(oldPhrase string, newPhrase string, newRounds int32) error {
	if err := envlp.validate(); err != nil {
		return err
	}

	kdf := envlp.getKDF()
	cipherSuite := envlp.getCipherSuite()

	key, err := kdf.Decrypt(envlp.ProtectedKey, oldPhrase)
	if err != nil {
		return err
	}

	if err := cipherSuite.checkHMAC(key, envlp.Data); err != nil {
		return err
	}

	protectedKey, err := kdf.Encrypt(key, newPhrase, newRounds)
	if err != nil {
		return err
	}

	envlp.ProtectedKey = protectedKey
	return nil
}
