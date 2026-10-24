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
type Box struct {
	aead cipher.AEAD
}

func NewBox(key [32]byte) *Box {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err) // only fails for invalid key sizes
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return &Box{aead: aead}
}

// Seal returns nonce || ciphertext.
func (b *Box) Seal(plaintext []byte) []byte {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return b.aead.Seal(nonce, nonce, plaintext, nil)
}

func (b *Box) Open(sealed []byte) ([]byte, error) {
	n := b.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("secret: ciphertext too short")
	}
	return b.aead.Open(nil, sealed[:n], sealed[n:], nil)
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
