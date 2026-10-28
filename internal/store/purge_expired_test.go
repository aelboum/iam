package store

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests pin PurgeExpired, which removes rows whose expires_at is in the
// past from every ephemeral protocol-state table (PurgedTables) in one call.
// They assert the actual database effect (the row is gone / still present),
// not merely a nil return, show that the purge acts globally by expiry rather
// than per tenant, and guard that PurgedTables stays in sync with the schema
// so a newly added ephemeral table cannot silently escape the purge (audit
// M7). Needs IAM_TEST_DATABASE_URL (shared helper lifecycleStore).

func rowExists(t *testing.T, pool *pgxpool.Pool, table, id string) bool {
	t.Helper()
	var n int
	// table is a fixed identifier from this test / PurgedTables, never input.
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM `+table+` WHERE id = $1`, id).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n > 0
}

// insertPair writes an access+refresh pair whose two rows both carry the given
// expiry, and returns their ids.
func insertPair(t *testing.T, st *Store, clientID, subject string, exp time.Time) (atID, rtID string) {
	t.Helper()
	atID, rtID = uuid.NewString(), uuid.NewString()
	at := &AccessToken{
		ID: atID, ClientID: clientID, Subject: subject, Audience: []string{clientID},
		Scopes: []string{}, RefreshTokenID: &rtID, ExpiresAt: exp,
	}
	rt := &RefreshToken{
		ID: rtID, TokenHash: uuid.NewString(), ClientID: clientID, Subject: subject,
		Audience: []string{clientID}, Scopes: []string{}, AMR: []string{}, AuthTime: time.Now(),
		AccessTokenID: &atID, ExpiresAt: exp, FamilyID: uuid.NewString(),
	}
	if err := st.CreateTokens(context.Background(), at, rt); err != nil {
		t.Fatalf("create tokens: %v", err)
	}
	return atID, rtID
}

func TestPurgeExpiredRemovesExpiredKeepsLive(t *testing.T) {
	st, pool := lifecycleStore(t)
	ctx := context.Background()

	// PurgeExpired deletes WHERE expires_at < now() (strict). A row a minute in
	// the past is removed; one an hour ahead is kept. The exact-equality edge
	// (expires_at == now()) is not asserted: it is a non-deterministic instant,
	// and the strict "<" means such a row is kept, which the live rows cover.
	past := time.Now().Add(-time.Minute)
	future := time.Now().Add(time.Hour)

	// Two tenants, to show the purge acts on expiry across all orgs at once and
	// never spares or targets a particular tenant.
	u1 := lifecycleUser(t, st, pool)
	u2 := lifecycleUser(t, st, pool)

	// access_tokens + refresh_tokens.
	expAT1, expRT1 := insertPair(t, st, "c1", u1.ID, past)
	liveAT1, liveRT1 := insertPair(t, st, "c1", u1.ID, future)
	expAT2, expRT2 := insertPair(t, st, "c2", u2.ID, past)
	liveAT2, liveRT2 := insertPair(t, st, "c2", u2.ID, future)

	// sessions.
	sExp, err := st.CreateSession(ctx, u1.OrgID, &u1.ID, "login", uuid.NewString(), past)
	if err != nil {
		t.Fatalf("create expired session: %v", err)
	}
	sLive, err := st.CreateSession(ctx, u2.OrgID, &u2.ID, "login", uuid.NewString(), future)
	if err != nil {
		t.Fatalf("create live session: %v", err)
	}

	// signing_keys.
	kExp := &SigningKey{ID: uuid.NewString(), Algorithm: "RS256", PrivateKeyEnc: []byte{1}, RotateAt: past, ExpiresAt: past}
	kLive := &SigningKey{ID: uuid.NewString(), Algorithm: "RS256", PrivateKeyEnc: []byte{1}, RotateAt: future, ExpiresAt: future}
	if err := st.InsertSigningKey(ctx, kExp); err != nil {
		t.Fatalf("insert expired key: %v", err)
	}
	if err := st.InsertSigningKey(ctx, kLive); err != nil {
		t.Fatalf("insert live key: %v", err)
	}

	if err := st.PurgeExpired(ctx); err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}

	// Expired rows for both tenants are gone.
	for _, g := range []struct {
		table, id string
	}{
		{"access_tokens", expAT1}, {"refresh_tokens", expRT1},
		{"access_tokens", expAT2}, {"refresh_tokens", expRT2},
		{"sessions", sExp.ID}, {"signing_keys", kExp.ID},
	} {
		if rowExists(t, pool, g.table, g.id) {
			t.Errorf("%s row %s expired but was not purged", g.table, g.id)
		}
	}

	// Live rows for both tenants survive.
	for _, g := range []struct {
		table, id string
	}{
		{"access_tokens", liveAT1}, {"refresh_tokens", liveRT1},
		{"access_tokens", liveAT2}, {"refresh_tokens", liveRT2},
		{"sessions", sLive.ID}, {"signing_keys", kLive.ID},
	} {
		if !rowExists(t, pool, g.table, g.id) {
			t.Errorf("%s row %s is live but was purged", g.table, g.id)
		}
	}
}

func TestPurgedTablesMatchSchema(t *testing.T) {
	_, pool := lifecycleStore(t)
	ctx := context.Background()

	// Every table PurgeExpired touches must actually have an expires_at column,
	// or its DELETE would fail at runtime.
	for _, tbl := range PurgedTables {
		var n int
		if err := pool.QueryRow(ctx, `
			SELECT count(*) FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = $1 AND column_name = 'expires_at'`, tbl).Scan(&n); err != nil {
			t.Fatalf("schema lookup %s: %v", tbl, err)
		}
		if n != 1 {
			t.Errorf("PurgedTables entry %q has no expires_at column; PurgeExpired would fail on it", tbl)
		}
	}

	// Reverse direction: every base table that has an expires_at column must be
	// either purged or a deliberate exclusion. api_keys carries an expiry but is
	// a long-lived credential whose lifetime is enforced at use and whose row is
	// retained for audit linkage, so it is intentionally not purged. Any OTHER
	// unpurged expires_at table is an audit-M7-class gap (ephemeral state
	// escaping the purge, as idp_intents/password_resets/webauthn_registrations
	// once did) and must be added to PurgedTables.
	//
	// Note: auth_requests also has a separate code_expires_at column; this query
	// matches only expires_at, and auth_requests is purged on its own expires_at
	// (the whole row goes when the request expires), so code_expires_at needs no
	// independent purge.
	excluded := map[string]bool{"api_keys": true}
	purged := map[string]bool{}
	for _, tbl := range PurgedTables {
		purged[tbl] = true
	}
	rows, err := pool.Query(ctx, `
		SELECT table_name FROM information_schema.columns
		WHERE table_schema = 'public' AND column_name = 'expires_at'`)
	if err != nil {
		t.Fatalf("schema scan: %v", err)
	}
	defer rows.Close()
	var gaps []string
	for rows.Next() {
		var tbl string
		if err := rows.Scan(&tbl); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if !purged[tbl] && !excluded[tbl] {
			gaps = append(gaps, tbl)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if len(gaps) > 0 {
		sort.Strings(gaps)
		t.Errorf("tables with an expires_at column neither purged nor a known exclusion: %v", gaps)
	}
}
