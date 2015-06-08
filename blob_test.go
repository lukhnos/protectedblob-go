package protectedblob // import "lukhnos.org/protectedblob"

import (
	"crypto/hmac"
	"testing"
)

var passphrase = "Complex-1234-😀"
var plaintext = []byte("hello, world, bonjour à tous, おはよう世界！")

func TestRoundTrip(t *testing.T) {
	envelope, err := Create(plaintext, passphrase, DefaultRounds)
	if err != nil {
		t.Error(err)
	}

	json, err := envelope.ToJSON()
	if err != nil {
		t.Error(err)
	}

	newEnvelope, err := FromJSON(json)
	if err != nil {
		t.Error(err)
	}

	decrypted, err := newEnvelope.GetPlaintext(passphrase)
	if err != nil {
		t.Error(err)
	}

	if !hmac.Equal(decrypted, plaintext) {
		t.Error("Decrypted plaintext does not match source")
	}
}

func TestChangePassphrase(t *testing.T) {
	envelope, err := Create(plaintext, passphrase, DefaultRounds)
	if err != nil {
		t.Error(err)
	}

	newPassphrase1 := "1234-5678-90-abcdef"
	if err := envelope.ChangePassphrase(passphrase, newPassphrase1); err != nil {
		t.Error(err)
	}

	decrypted, err := envelope.GetPlaintext(newPassphrase1)
	if err != nil {
		t.Error(err)
	}

	if !hmac.Equal(decrypted, plaintext) {
		t.Error("Decrypted plaintext does not match source")
	}

	_, err = envelope.GetPlaintext(passphrase)
	if err == nil {
		t.Error("Decrypting with old passphrase should fail")
	} else if err.Error() != hmacError().Error() {
		t.Error("Not the expected HMAC error")
	}
}

func TestEmptyEnvelope(t *testing.T) {
	envelope := Envelope{}
	if _, err := envelope.GetPlaintext(passphrase); err == nil {
		t.Error("Empty envelope must not give out anything")
	}
}

func expectBadEnvelopeShouldFail(t *testing.T, badEnvelope Envelope) {
	if _, err := badEnvelope.GetPlaintext(passphrase); err == nil {
		t.Error("Bad envelope should fail")
	}
}

func TestCorruptEnvelope(t *testing.T) {
	envelope, err := Create(plaintext, passphrase, DefaultRounds)
	if err != nil {
		t.Error(err)
	}

	badEnvelope := envelope
	badEnvelope.Version = ""
	expectBadEnvelopeShouldFail(t, badEnvelope)

	badEnvelope = envelope
	badEnvelope.KDF = ""
	expectBadEnvelopeShouldFail(t, badEnvelope)

	badEnvelope = envelope
	badEnvelope.CipherSuite = ""
	expectBadEnvelopeShouldFail(t, badEnvelope)

	badEnvelope = envelope
	badEnvelope.ProtectedKey.Salt = []byte{}
	expectBadEnvelopeShouldFail(t, badEnvelope)

	badEnvelope = envelope
	badEnvelope.ProtectedKey.Rounds = 0
	expectBadEnvelopeShouldFail(t, badEnvelope)

	badEnvelope = envelope
	badEnvelope.ProtectedKey.EncryptedKey = []byte{}
	expectBadEnvelopeShouldFail(t, badEnvelope)

	badEnvelope = envelope
	badEnvelope.Data.IV = []byte{}
	expectBadEnvelopeShouldFail(t, badEnvelope)

	badEnvelope = envelope
	badEnvelope.Data.Ciphertext = []byte{}
	expectBadEnvelopeShouldFail(t, badEnvelope)

	badEnvelope = envelope
	badEnvelope.Data.HMAC = []byte{}
	expectBadEnvelopeShouldFail(t, badEnvelope)

	if _, err := envelope.GetPlaintext(passphrase); err != nil {
		t.Error("Original envelope should be good:", err)
	}
}
