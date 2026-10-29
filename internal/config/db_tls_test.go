package config

import "testing"

// DatabaseUsesTLS must report plaintext for sslmode=disable and TLS for every
// mode that attempts or requires it, so the production startup warning fires
// exactly when the connection to Postgres is unencrypted.
func TestDatabaseUsesTLS(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want bool
	}{
		{"disable is plaintext", "postgres://iam:pw@localhost:5432/iam?sslmode=disable", false},
		{"require uses tls", "postgres://iam:pw@localhost:5432/iam?sslmode=require", true},
		{"verify-full uses tls", "postgres://iam:pw@db.example.com:5432/iam?sslmode=verify-full", true},
		{"prefer uses tls", "postgres://iam:pw@localhost:5432/iam?sslmode=prefer", true},
		{"default (no sslmode) uses tls", "postgres://iam:pw@localhost:5432/iam", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DatabaseUsesTLS(tc.url)
			if err != nil {
				t.Fatalf("DatabaseUsesTLS(%q) error: %v", tc.url, err)
			}
			if got != tc.want {
				t.Errorf("DatabaseUsesTLS(%q) = %v, want %v", tc.url, got, tc.want)
			}
		})
	}
}

func TestDatabaseUsesTLSInvalidURL(t *testing.T) {
	if _, err := DatabaseUsesTLS("://not a url"); err == nil {
		t.Error("expected error for malformed database URL, got nil")
	}
}
