package secret

import (
	"bytes"
	"testing"
)

func TestBoxRotation(t *testing.T) {
	oldKey, newKey, otherKey := [32]byte{1}, [32]byte{2}, [32]byte{3}

	sealedOld := NewBox(oldKey).Seal([]byte("secret"))

	rotating := NewBox(newKey, oldKey)
	plain, current, err := rotating.OpenCurrent(sealedOld)
	if err != nil || !bytes.Equal(plain, []byte("secret")) {
		t.Fatalf("previous key must still decrypt: %v", err)
	}
	if current {
		t.Fatal("data sealed with the previous key must be reported as not current")
	}

	resealed := rotating.Seal(plain)
	if _, current, _ := rotating.OpenCurrent(resealed); !current {
		t.Fatal("Seal must use the current key")
	}
	if _, err := NewBox(newKey).Open(resealed); err != nil {
		t.Fatal("after rotation the old key is no longer needed")
	}
	if _, err := NewBox(otherKey).Open(sealedOld); err == nil {
		t.Fatal("an unrelated key must not decrypt")
	}
}

func TestHMACIsKeyed(t *testing.T) {
	if HMAC([32]byte{1}, "m") == HMAC([32]byte{2}, "m") {
		t.Fatal("different keys must give different MACs")
	}
	// Assigned first: staticcheck flags two identical call expressions on
	// either side of a comparison (SA4000), even though determinism is exactly
	// what this asserts.
	first, second := HMAC([32]byte{1}, "m"), HMAC([32]byte{1}, "m")
	if first != second {
		t.Fatal("HMAC must be deterministic")
	}
}
