package authn

import (
	"bufio"
	_ "embed"
	"fmt"
	"io"
	"os"
	"strings"
)

//go:embed weakpasswords.txt
var embeddedWeakPasswords string

// weakPasswords is the lowercased breached/common-password denylist. It is
// seeded from the embedded list at package init and may be extended once at
// startup from an operator-supplied file (IAM_WEAK_PASSWORD_FILE) before the
// server begins handling requests. It is only read afterwards, so no lock is
// needed for the request path.
var weakPasswords = parseWeakPasswords(strings.NewReader(embeddedWeakPasswords))

// parseWeakPasswords reads one password per line, skipping blank lines and
// lines starting with '#', and returns the set lowercased and trimmed.
func parseWeakPasswords(r io.Reader) map[string]struct{} {
	m := make(map[string]struct{})
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m[strings.ToLower(line)] = struct{}{}
	}
	return m
}

// AddWeakPasswordFile merges an operator-supplied denylist into the in-memory
// set. It is meant to be called once at startup (IAM_WEAK_PASSWORD_FILE); a
// larger offline corpus such as the Have I Been Pwned "Pwned Passwords"
// top-N export can be dropped in without rebuilding the binary.
func AddWeakPasswordFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open weak-password file: %w", err)
	}
	defer f.Close()
	for pw := range parseWeakPasswords(f) {
		weakPasswords[pw] = struct{}{}
	}
	return nil
}

// isWeakPassword reports whether pw appears in the breached/common denylist,
// compared case-insensitively with surrounding whitespace trimmed.
func isWeakPassword(pw string) bool {
	_, ok := weakPasswords[strings.ToLower(strings.TrimSpace(pw))]
	return ok
}
