package config

import (
	"encoding/base64"
	"testing"
)

// setValidBaseEnv sets the minimum environment for Load to succeed, so a test
// can then vary one sizing variable in isolation.
func setValidBaseEnv(t *testing.T) {
	t.Helper()
	t.Setenv("IAM_ISSUER", "https://auth.example.com")
	t.Setenv("IAM_DATABASE_URL", "postgres://u:p@localhost:5432/iam")
	t.Setenv("IAM_MASTER_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
}

func TestLoadHashSlots(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		set     bool
		want    int
		wantErr bool
	}{
		{name: "unset means auto (0)", set: false, want: 0},
		{name: "explicit zero is auto", value: "0", set: true, want: 0},
		{name: "positive override", value: "6", set: true, want: 6},
		{name: "at the cap", value: "1024", set: true, want: 1024},
		{name: "above the cap", value: "1025", set: true, wantErr: true},
		{name: "negative", value: "-1", set: true, wantErr: true},
		{name: "not an integer", value: "lots", set: true, wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			setValidBaseEnv(t)
			if c.set {
				t.Setenv("IAM_HASH_SLOTS", c.value)
			}
			cfg, err := Load()
			if c.wantErr {
				if err == nil {
					t.Fatalf("IAM_HASH_SLOTS=%q: want error, got cfg.HashSlots=%d", c.value, cfg.HashSlots)
				}
				return
			}
			if err != nil {
				t.Fatalf("IAM_HASH_SLOTS=%q: unexpected error: %v", c.value, err)
			}
			if cfg.HashSlots != c.want {
				t.Fatalf("IAM_HASH_SLOTS=%q: HashSlots=%d, want %d", c.value, cfg.HashSlots, c.want)
			}
		})
	}
}

func TestLoadStrictSizing(t *testing.T) {
	for _, c := range []struct {
		value string
		set   bool
		want  bool
	}{
		{set: false, want: false},
		{value: "true", set: true, want: true},
		{value: "false", set: true, want: false},
		{value: "1", set: true, want: false}, // only "true" enables it
	} {
		setValidBaseEnv(t)
		if c.set {
			t.Setenv("IAM_STRICT_SIZING", c.value)
		}
		cfg, err := Load()
		if err != nil {
			t.Fatalf("IAM_STRICT_SIZING=%q: unexpected error: %v", c.value, err)
		}
		if cfg.StrictSizing != c.want {
			t.Fatalf("IAM_STRICT_SIZING=%q: StrictSizing=%v, want %v", c.value, cfg.StrictSizing, c.want)
		}
	}
}
