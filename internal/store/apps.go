package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// App is an OIDC client belonging to a project.
type App struct {
	ID                     string    `json:"id"`
	ProjectID              string    `json:"project_id"`
	Name                   string    `json:"name"`
	ClientID               string    `json:"client_id"`
	ClientSecretHash       *string   `json:"-"`
	AppType                string    `json:"app_type"`    // web | spa | native
	AuthMethod             string    `json:"auth_method"` // client_secret_basic | client_secret_post | none
	RedirectURIs           []string  `json:"redirect_uris"`
	PostLogoutRedirectURIs []string  `json:"post_logout_redirect_uris"`
	AccessTokenType        string    `json:"access_token_type"` // jwt | bearer
	LoginURL               string    `json:"login_url"`
	DevMode                bool      `json:"dev_mode"`
	CreatedAt              time.Time `json:"created_at"`
}

const appColumns = `id, project_id, name, client_id, client_secret_hash, app_type, auth_method,
	redirect_uris, post_logout_redirect_uris, access_token_type, login_url, dev_mode, created_at`

func scanApp(row interface{ Scan(...any) error }) (*App, error) {
	var a App
	if err := row.Scan(&a.ID, &a.ProjectID, &a.Name, &a.ClientID, &a.ClientSecretHash, &a.AppType,
		&a.AuthMethod, &a.RedirectURIs, &a.PostLogoutRedirectURIs, &a.AccessTokenType, &a.LoginURL,
		&a.DevMode, &a.CreatedAt); err != nil {
		return nil, mapErr(err)
	}
	return &a, nil
}

// CreateApp inserts a; ID and CreatedAt are assigned by the store.
func (s *Store) CreateApp(ctx context.Context, a App) (*App, error) {
	return scanApp(s.pool.QueryRow(ctx, `
		INSERT INTO apps (id, project_id, name, client_id, client_secret_hash, app_type, auth_method,
			redirect_uris, post_logout_redirect_uris, access_token_type, login_url, dev_mode)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING `+appColumns,
		uuid.NewString(), a.ProjectID, a.Name, a.ClientID, a.ClientSecretHash, a.AppType, a.AuthMethod,
		a.RedirectURIs, a.PostLogoutRedirectURIs, a.AccessTokenType, a.LoginURL, a.DevMode))
}

func (s *Store) GetApp(ctx context.Context, id string) (*App, error) {
	return scanApp(s.pool.QueryRow(ctx, `SELECT `+appColumns+` FROM apps WHERE id = $1`, id))
}

func (s *Store) GetAppByClientID(ctx context.Context, clientID string) (*App, error) {
	return scanApp(s.pool.QueryRow(ctx, `SELECT `+appColumns+` FROM apps WHERE client_id = $1`, clientID))
}

func (s *Store) ListApps(ctx context.Context, projectID string, p Page) ([]*App, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+appColumns+` FROM apps WHERE project_id = $1 ORDER BY created_at, id`+p.sql(), projectID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	apps := []*App{}
	for rows.Next() {
		a, err := scanApp(rows)
		if err != nil {
			return nil, err
		}
		apps = append(apps, a)
	}
	return apps, mapErr(rows.Err())
}

func (s *Store) DeleteApp(ctx context.Context, id string) error {
	return s.execOne(ctx, `DELETE FROM apps WHERE id = $1`, id)
}
