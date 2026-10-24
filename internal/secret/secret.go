// Package secret holds small crypto helpers: random tokens, token hashing
// and AES-GCM encryption of secrets stored in the database.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

// Token returns a URL-safe random string with n bytes of entropy.
func Token(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Hash returns the hex SHA-256 of a high-entropy token. Do not use for passwords.
func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// HMAC returns the hex HMAC-SHA256 of msg under key.
func HMAC(key [32]byte, msg string) string {
	m := hmac.New(sha256.New, key[:])
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}

// Equal compares two strings in constant time.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Box encrypts and decrypts values with AES-256-GCM.
// It seals with the first key and opens with any of them, so the master key
// can be rotated: deploy the new key first with the old one as a fallback,
// re-encrypt (iamd rotate-keys), then drop the old key.
type Box struct {
	aeads []cipher.AEAD
}

func NewBox(key [32]byte, previous ...[32]byte) *Box {
	b := &Box{}
	for _, k := range append([][32]byte{key}, previous...) {
		block, err := aes.NewCipher(k[:])
		if err != nil {
			panic(err) // only fails for invalid key sizes
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			panic(err)
		}
		b.aeads = append(b.aeads, aead)
	}
	return b
}

// Seal returns nonce || ciphertext, encrypted with the current key.
func (b *Box) Seal(plaintext []byte) []byte {
	aead := b.aeads[0]
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return aead.Seal(nonce, nonce, plaintext, nil)
}

// Open decrypts with the current key or, failing that, a previous one.
func (b *Box) Open(sealed []byte) ([]byte, error) {
	plain, _, err := b.OpenCurrent(sealed)
	return plain, err
}

// OpenCurrent also reports whether sealed used the current key; false means
// it should be re-encrypted.
func (b *Box) OpenCurrent(sealed []byte) (plain []byte, current bool, err error) {
	for i, aead := range b.aeads {
		n := aead.NonceSize()
		if len(sealed) < n {
			return nil, false, errors.New("secret: ciphertext too short")
		}
		if plain, err := aead.Open(nil, sealed[:n], sealed[n:], nil); err == nil {
			return plain, i == 0, nil
		}
	}
	return nil, false, errors.New("secret: cannot decrypt with any configured key")
}

// Derive returns a sub-key bound to a purpose label.
func Derive(master [32]byte, purpose string) [32]byte {
	h := sha256.New()
	h.Write(master[:])
	h.Write([]byte(purpose))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
