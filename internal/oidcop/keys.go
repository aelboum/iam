package oidcop

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/aelboum/iam/internal/secret"
	"github.com/aelboum/iam/internal/store"
)

// keyCacheTTL bounds how long a rotated key can go unnoticed by other instances.
// It is the production default for keyStore.cacheTTL; tests may shorten the
// per-store field to exercise cache expiry deterministically.
const keyCacheTTL = time.Minute

// publishLead is how long a new key is published in the JWKS before it signs
// anything, so every instance and relying party has seen it (> keyCacheTTL).
// It is the production default for keyStore.pubLead.
const publishLead = 3 * keyCacheTTL

type signingKey struct {
	id        string
	priv      *rsa.PrivateKey
	createdAt time.Time
	rotateAt  time.Time
}

func (k *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k *signingKey) Key() any                                    { return k.priv }
func (k *signingKey) ID() string                                  { return k.id }

type publicKey struct {
	*signingKey
}

func (k publicKey) Algorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k publicKey) Use() string                        { return "sig" }
func (k publicKey) Key() any                           { return &k.priv.PublicKey }

// keyStore manages RSA signing keys in the database with automatic rotation.
// A key signs for one rotation interval, then stays published in the JWKS for
// another interval so tokens signed with it remain verifiable.
type keyStore struct {
	store    *store.Store
	box      *secret.Box
	rotation time.Duration

	// now, cacheTTL and pubLead are a minimal seam (CRYPTO-05 Phase 1): they
	// default to time.Now, keyCacheTTL and publishLead in production and are
	// only overridden in tests so cache expiry and publication timing can be
	// driven deterministically without sleeps. They never change behavior when
	// left at their defaults.
	now      func() time.Time
	cacheTTL time.Duration
	pubLead  time.Duration

	mu       sync.Mutex
	keys     []*signingKey // newest first
	loadedAt time.Time
}

func newKeyStore(st *store.Store, box *secret.Box, rotation time.Duration) *keyStore {
	return &keyStore{
		store:    st,
		box:      box,
		rotation: rotation,
		now:      time.Now,
		cacheTTL: keyCacheTTL,
		pubLead:  publishLead,
	}
}

func (ks *keyStore) current(ctx context.Context) (*signingKey, []*signingKey, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.now().Sub(ks.loadedAt) > ks.cacheTTL || len(ks.keys) == 0 || needsNewKey(ks.keys, ks.now(), ks.pubLead) {
		if err := ks.reload(ctx); err != nil {
			return nil, nil, err
		}
	}
	return signer(ks.keys, ks.now(), ks.pubLead), ks.keys, nil
}

// needsNewKey reports whether the newest key is close enough to rotation
// that its successor must be published now.
func needsNewKey(keys []*signingKey, now time.Time, pubLead time.Duration) bool {
	return len(keys) == 0 || now.After(keys[0].rotateAt.Add(-pubLead))
}

// signer picks the newest key that has been published for at least
// pubLead. Right after first start there is only one key, which is used.
func signer(keys []*signingKey, now time.Time, pubLead time.Duration) *signingKey {
	cutoff := now.Add(-pubLead)
	for _, k := range keys { // newest first
		if !k.createdAt.After(cutoff) {
			return k
		}
	}
	return keys[len(keys)-1]
}

func (ks *keyStore) reload(ctx context.Context) error {
	keys, err := ks.load(ctx)
	if err != nil {
		return err
	}
	if needsNewKey(keys, ks.now(), ks.pubLead) {
		err := ks.store.LockSigningKeys(ctx, func(ctx context.Context) error {
			// Another instance may have rotated while we waited for the lock.
			if keys, err = ks.load(ctx); err != nil {
				return err
			}
			if !needsNewKey(keys, ks.now(), ks.pubLead) {
				return nil
			}
			if err := ks.generate(ctx); err != nil {
				return err
			}
			keys, err = ks.load(ctx)
			return err
		})
		if err != nil {
			return err
		}
	}
	if len(keys) == 0 {
		return errors.New("no signing key available")
	}
	ks.keys = keys
	ks.loadedAt = ks.now()
	return nil
}

func (ks *keyStore) load(ctx context.Context) ([]*signingKey, error) {
	rows, err := ks.store.ListSigningKeys(ctx)
	if err != nil {
		return nil, err
	}
	keys := make([]*signingKey, 0, len(rows))
	for _, row := range rows {
		der, err := ks.box.Open(row.PrivateKeyEnc)
		if err != nil {
			return nil, fmt.Errorf("decrypt signing key %s: %w", row.ID, err)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("parse signing key %s: %w", row.ID, err)
		}
		priv, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("signing key %s is not RSA", row.ID)
		}
		keys = append(keys, &signingKey{id: row.ID, priv: priv, createdAt: row.CreatedAt, rotateAt: row.RotateAt})
	}
	return keys, nil
}

func (ks *keyStore) generate(ctx context.Context) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	now := ks.now()
	return ks.store.InsertSigningKey(ctx, &store.SigningKey{
		ID:            uuid.NewString(),
		Algorithm:     string(jose.RS256),
		PrivateKeyEnc: ks.box.Seal(der),
		RotateAt:      now.Add(ks.rotation),
		ExpiresAt:     now.Add(2 * ks.rotation),
	})
}

func (ks *keyStore) SigningKey(ctx context.Context) (op.SigningKey, error) {
	key, _, err := ks.current(ctx)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (ks *keyStore) KeySet(ctx context.Context) ([]op.Key, error) {
	_, keys, err := ks.current(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]op.Key, 0, len(keys))
	for _, k := range keys {
		out = append(out, publicKey{k})
	}
	return out, nil
}
