package authn

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// CheckPasswordPolicy must reject passwords on the breached/common denylist,
// case-insensitively, while accepting a strong password of the same length.
func TestCheckPasswordPolicyRejectsCommonPassword(t *testing.T) {
	const user, email = "alice", "alice@example.test"

	// A common password long enough to pass the length gate must still be
	// rejected by the denylist.
	for _, pw := range []string{"password123", "PASSWORD123", "welcome1234", "qwerty12345"} {
		if err := CheckPasswordPolicy(pw, user, email); err == nil {
			t.Errorf("CheckPasswordPolicy accepted common password %q, want rejected", pw)
		}
	}

	// A strong, uncommon password of adequate length is accepted.
	if err := CheckPasswordPolicy("tr4ns-horse-battery-staple", user, email); err != nil {
		t.Errorf("CheckPasswordPolicy rejected a strong password: %v", err)
	}
}

func TestParseWeakPasswordsSkipsCommentsAndBlanks(t *testing.T) {
	in := "# a comment\n\n  Hunter2Hunter  \n# another\nSpaced Entry\n"
	m := parseWeakPasswords(strings.NewReader(in))
	if _, ok := m["hunter2hunter"]; !ok {
		t.Error("expected trimmed, lowercased entry present")
	}
	if _, ok := m["spaced entry"]; !ok {
		t.Error("expected multi-word entry present")
	}
	if _, ok := m["# a comment"]; ok {
		t.Error("comment line must not be an entry")
	}
	if len(m) != 2 {
		t.Errorf("want 2 entries, got %d", len(m))
	}
}

func TestAddWeakPasswordFileMerges(t *testing.T) {
	const custom = "ourcompanyname2026"
	if isWeakPassword(custom) {
		t.Fatalf("precondition: %q should not be weak before merge", custom)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "extra.txt")
	if err := os.WriteFile(path, []byte("# ours\n"+custom+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AddWeakPasswordFile(path); err != nil {
		t.Fatalf("AddWeakPasswordFile: %v", err)
	}
	if !isWeakPassword(custom) {
		t.Errorf("after merge, %q should be rejected as weak", custom)
	}
	if err := AddWeakPasswordFile(filepath.Join(dir, "does-not-exist.txt")); err == nil {
		t.Error("AddWeakPasswordFile should error on a missing file")
	}
}
