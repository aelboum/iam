package store

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type User struct {
	ID            string  `json:"id"`
	OrgID         string  `json:"org_id"`
	Username      string  `json:"username"`
	Email         string  `json:"email"`
	EmailVerified bool    `json:"email_verified"`
	GivenName     string  `json:"given_name"`
	FamilyName    string  `json:"family_name"`
	PasswordHash  *string `json:"-"`
	TOTPSecretEnc []byte  `json:"-"`
	TOTPVerified  bool    `json:"totp_enabled"`
	FailedLogins  int     `json:"-"`
	// Locked is a manual lock set by an administrator.
	Locked bool `json:"locked"`
	// LockedUntil is the temporary lockout after too many failed password logins.
	LockedUntil *time.Time `json:"locked_until"`
	// MfaLockedUntil is the temporary lockout after too many failed TOTP attempts
	// (internal security audit N11).
	MfaLockedUntil *time.Time `json:"-"`
	TOTPLastStep   *int64     `json:"-"`
	// Kind is human (logs in interactively) or machine (client credentials).
	Kind             string    `json:"kind"`
	ClientID         *string   `json:"client_id,omitempty"`
	ClientSecretHash *string   `json:"-"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

const (
	KindHuman   = "human"
	KindMachine = "machine"
)

func (u *User) HasPassword() bool { return u.PasswordHash != nil }

// CreateMachineUser adds a machine user that authenticates with client
// credentials. Machine users have no email or password and cannot log in
// through the session API.
func (s *Store) CreateMachineUser(ctx context.Context, orgID, name, clientID, secretHash string) (*User, error) {
	id := uuid.NewString()
	return scanUser(s.pool.QueryRow(ctx, `
		INSERT INTO users (id, org_id, username, email, email_verified, given_name, kind, client_id, client_secret_hash)
		VALUES ($1, $2, $3, $4, true, $3, 'machine', $5, $6) RETURNING `+userColumns,
		id, orgID, name, id+"@machine.invalid", clientID, secretHash))
}

// GetMachineUserByClientID finds an unlocked machine user by its client id.
func (s *Store) GetMachineUserByClientID(ctx context.Context, clientID string) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE client_id = $1 AND kind = 'machine'`, clientID))
}

// SetClientSecret replaces a machine user's secret.
func (s *Store) SetClientSecret(ctx context.Context, userID, secretHash string) error {
	return s.execOne(ctx, `UPDATE users SET client_secret_hash = $2, updated_at = now() WHERE id = $1 AND kind = 'machine'`, userID, secretHash)
}

// MFARequired reports whether login must include a second factor.
func (u *User) MFARequired() bool { return u.TOTPVerified }

// IsLocked reports a manual lock or an active temporary password lockout.
func (u *User) IsLocked() bool {
	return u.Locked || (u.LockedUntil != nil && u.LockedUntil.After(time.Now()))
}

// IsMFALocked reports a manual lock or an active temporary TOTP lockout. A
// password lockout (LockedUntil) deliberately does not block the TOTP step, so
// a password-guesser cannot deny a valid SSO user's second factor; a TOTP
// lockout still blocks the password and reset paths via ReserveAttempt
// (internal security audit N11).
func (u *User) IsMFALocked() bool {
	return u.Locked || (u.MfaLockedUntil != nil && u.MfaLockedUntil.After(time.Now()))
}

const userColumns = `id, org_id, username, email, email_verified, given_name, family_name,
	password_hash, totp_secret_enc, totp_verified, failed_logins, locked, locked_until,
	mfa_locked_until, totp_last_step, created_at, updated_at, kind, client_id, client_secret_hash`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	if err := row.Scan(&u.ID, &u.OrgID, &u.Username, &u.Email, &u.EmailVerified, &u.GivenName,
		&u.FamilyName, &u.PasswordHash, &u.TOTPSecretEnc, &u.TOTPVerified, &u.FailedLogins,
		&u.Locked, &u.LockedUntil, &u.MfaLockedUntil, &u.TOTPLastStep, &u.CreatedAt, &u.UpdatedAt, &u.Kind, &u.ClientID,
		&u.ClientSecretHash); err != nil {
		return nil, mapErr(err)
	}
	return &u, nil
}

type NewUser struct {
	OrgID         string
	Username      string
	Email         string
	EmailVerified bool
	GivenName     string
	FamilyName    string
	PasswordHash  *string
}

func (s *Store) CreateUser(ctx context.Context, n NewUser) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `
		INSERT INTO users (id, org_id, username, email, email_verified, given_name, family_name, password_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING `+userColumns,
		uuid.NewString(), n.OrgID, n.Username, n.Email, n.EmailVerified, n.GivenName, n.FamilyName, n.PasswordHash))
}

func (s *Store) GetUser(ctx context.Context, id string) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id))
}

// FindUserForLogin resolves a login name within an org. A name containing "@"
// is matched against emails only (unique per org), anything else against
// usernames only, so a username can never shadow someone else's email.
func (s *Store) FindUserForLogin(ctx context.Context, orgID, loginName string) (*User, error) {
	if strings.Contains(loginName, "@") {
		return scanUser(s.pool.QueryRow(ctx,
			`SELECT `+userColumns+` FROM users WHERE org_id = $1 AND kind = 'human' AND lower(email) = lower($2)`, orgID, loginName))
	}
	return scanUser(s.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE org_id = $1 AND kind = 'human' AND lower(username) = lower($2)`, orgID, loginName))
}

func (s *Store) ListUsers(ctx context.Context, orgID string, p Page) ([]*User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userColumns+` FROM users WHERE org_id = $1 ORDER BY created_at, id`+p.sql(), orgID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	users := []*User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, mapErr(rows.Err())
}

// UserPatch holds optional profile updates; nil fields are left unchanged.
type UserPatch struct {
	Email         *string `json:"email"`
	EmailVerified *bool   `json:"email_verified"`
	GivenName     *string `json:"given_name"`
	FamilyName    *string `json:"family_name"`
}

// UpdateUser applies p. Changing the email clears email_verified unless the
// patch sets email_verified explicitly.
func (s *Store) UpdateUser(ctx context.Context, id string, p UserPatch) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `
		UPDATE users SET
			email          = COALESCE($2, email),
			email_verified = COALESCE($3,
				CASE WHEN $2::text IS NOT NULL AND lower($2::text) <> lower(email) THEN false ELSE email_verified END),
			given_name     = COALESCE($4, given_name),
			family_name    = COALESCE($5, family_name),
			updated_at     = now()
		WHERE id = $1 RETURNING `+userColumns,
		id, p.Email, p.EmailVerified, p.GivenName, p.FamilyName))
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	return s.execOne(ctx, `DELETE FROM users WHERE id = $1`, id)
}

func (s *Store) SetPasswordHash(ctx context.Context, id, hash string) error {
	return s.execOne(ctx, `UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1`, id, hash)
}

// RecordFailedLogin counts a failed attempt. Once max is reached the user is
// locked out temporarily for lockFor and the counter starts over, so an
// attacker can delay a user but never lock them out permanently.
// Password and TOTP failures are counted separately: a correct password
// resets only the password counter, so knowing the password does not give
// unlimited TOTP guesses.
//
// Each attempt is reserved (counted) before the credential is verified, and
// the reservation fails once max attempts are counted. So no matter how many
// requests race in parallel, at most max guesses are evaluated per lockout
// window.

// Factor selects the failure counter.
type Factor string

const (
	FactorPassword Factor = "failed_logins"
	FactorTOTP     Factor = "mfa_failed_logins"
)

// lockCol is the temporary-lockout column a failure of factor f sets.
func lockCol(f Factor) string {
	if f == FactorTOTP {
		return "mfa_locked_until"
	}
	return "locked_until"
}

// lockBlocks is the SQL predicate that must hold for a new attempt of factor f
// to be allowed: no manual lock and no lockout that blocks f is active. A TOTP
// lockout (mfa_locked_until) blocks both factors, so it cannot be bypassed by
// falling back to the password or reset path (anti-bypass); a password lockout
// (locked_until) blocks only the password factor (internal security audit N11).
func lockBlocks(f Factor) string {
	mfa := "(mfa_locked_until IS NULL OR mfa_locked_until <= now())"
	if f == FactorTOTP {
		return "NOT locked AND " + mfa
	}
	return "NOT locked AND (locked_until IS NULL OR locked_until <= now()) AND " + mfa
}

// ReserveAttempt counts an attempt. It returns false if the user is locked for
// this factor or max attempts are already counted (possibly by requests still
// running).
func (s *Store) ReserveAttempt(ctx context.Context, id string, f Factor, max int) (bool, error) {
	col := string(f) // fixed column name, never user input
	tag, err := s.pool.Exec(ctx, `
		UPDATE users SET `+col+` = `+col+` + 1
		WHERE id = $1 AND `+col+` < $2 AND `+lockBlocks(f),
		id, max)
	if err != nil {
		return false, mapErr(err)
	}
	return tag.RowsAffected() == 1, nil
}

// AttemptFailed is called after a reserved attempt failed. Once max attempts
// are counted the user is locked out for lockFor and the counter starts over.
func (s *Store) AttemptFailed(ctx context.Context, id string, f Factor, max int, lockFor time.Duration) (locked bool, err error) {
	col := string(f)
	lc := lockCol(f) // fixed column name, never user input
	err = s.pool.QueryRow(ctx, `
		UPDATE users SET
			`+lc+`  = CASE WHEN `+col+` >= $2 THEN now() + make_interval(secs => $3) ELSE `+lc+` END,
			`+col+` = CASE WHEN `+col+` >= $2 THEN 0 ELSE `+col+` END
		WHERE id = $1 RETURNING `+lc+` IS NOT NULL AND `+lc+` > now()`,
		id, max, lockFor.Seconds()).Scan(&locked)
	return locked, mapErr(err)
}

// AttemptSucceeded clears the counter after a reserved attempt succeeded.
func (s *Store) AttemptSucceeded(ctx context.Context, id string, f Factor) error {
	return s.execOne(ctx, `UPDATE users SET `+string(f)+` = 0 WHERE id = $1`, id)
}

// ReleaseAttempt undoes a ReserveAttempt that was never settled by a success or
// a failure — for example when hashing was shed under overload before the
// password could be evaluated. It decrements only the single attempt it
// reserved (never below zero, so a concurrent reservation is left intact),
// instead of clearing the counter, so a transient shed cannot advance a real
// user toward lockout (internal security audit N12).
func (s *Store) ReleaseAttempt(ctx context.Context, id string, f Factor) error {
	col := string(f) // fixed column name, never user input
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET `+col+` = `+col+` - 1 WHERE id = $1 AND `+col+` > 0`, id)
	return mapErr(err)
}

// UpgradePasswordHash replaces a hash with a stronger one, but only if it is
// still oldHash, so it can never undo a concurrent password change.
func (s *Store) UpgradePasswordHash(ctx context.Context, id, oldHash, newHash string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET password_hash = $3 WHERE id = $1 AND password_hash = $2`, id, oldHash, newHash)
	return mapErr(err)
}

// SetLocked sets or clears the manual lock and clears any temporary lockout.
func (s *Store) SetLocked(ctx context.Context, id string, locked bool) error {
	return s.execOne(ctx, `
		UPDATE users SET locked = $2, locked_until = NULL, mfa_locked_until = NULL,
			failed_logins = 0, mfa_failed_logins = 0, updated_at = now()
		WHERE id = $1`, id, locked)
}

// DeleteUserSessions ends every login in progress for a user.
// It also invalidates outstanding password reset tokens, because it is called
// on every credential change (TOTP, passkeys, email), see audit M12.
func (s *Store) DeleteUserSessions(ctx context.Context, userID string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID); err != nil {
			return mapErr(err)
		}
		_, err := tx.Exec(ctx, `DELETE FROM password_resets WHERE user_id = $1`, userID)
		return mapErr(err)
	})
}

// SetPendingTOTP stores a new, not yet verified TOTP secret.
func (s *Store) SetPendingTOTP(ctx context.Context, id string, secretEnc []byte) error {
	return s.execOne(ctx, `UPDATE users SET totp_secret_enc = $2, totp_verified = false, totp_last_step = NULL, updated_at = now() WHERE id = $1`, id, secretEnc)
}

// AcceptTOTPStep records step as used. It returns false if this or a later
// step was already used, which rejects replayed codes.
func (s *Store) AcceptTOTPStep(ctx context.Context, id string, step int64) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE users SET totp_last_step = $2
		WHERE id = $1 AND (totp_last_step IS NULL OR totp_last_step < $2)`, id, step)
	if err != nil {
		return false, mapErr(err)
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) MarkTOTPVerified(ctx context.Context, id string) error {
	return s.execOne(ctx, `UPDATE users SET totp_verified = true, updated_at = now() WHERE id = $1 AND totp_secret_enc IS NOT NULL`, id)
}

func (s *Store) RemoveTOTP(ctx context.Context, id string) error {
	return s.execOne(ctx, `UPDATE users SET totp_secret_enc = NULL, totp_verified = false, updated_at = now() WHERE id = $1`, id)
}
