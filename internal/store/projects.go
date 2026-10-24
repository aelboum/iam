package store

import (
	"context"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Project struct {
	ID         string    `json:"id"`
	OwnerOrgID string    `json:"owner_org_id"`
	Name       string    `json:"name"`
	CreatedAt  time.Time `json:"created_at"`
}

type Role struct {
	Key         string `json:"key"`
	DisplayName string `json:"display_name"`
}

// ProjectGrant makes a project and a subset of its roles available to another org.
type ProjectGrant struct {
	ID           string    `json:"id"`
	ProjectID    string    `json:"project_id"`
	GrantedOrgID string    `json:"granted_org_id"`
	RoleKeys     []string  `json:"role_keys"`
	CreatedAt    time.Time `json:"created_at"`
}

// UserGrant assigns project roles to a user.
type UserGrant struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	ProjectID string    `json:"project_id"`
	RoleKeys  []string  `json:"role_keys"`
	CreatedAt time.Time `json:"created_at"`
}

// --- projects ---------------------------------------------------------------

const projectColumns = `id, owner_org_id, name, created_at`

func scanProject(row interface{ Scan(...any) error }) (*Project, error) {
	var p Project
	if err := row.Scan(&p.ID, &p.OwnerOrgID, &p.Name, &p.CreatedAt); err != nil {
		return nil, mapErr(err)
	}
	return &p, nil
}

func (s *Store) CreateProject(ctx context.Context, ownerOrgID, name string) (*Project, error) {
	return scanProject(s.pool.QueryRow(ctx,
		`INSERT INTO projects (id, owner_org_id, name) VALUES ($1, $2, $3) RETURNING `+projectColumns,
		uuid.NewString(), ownerOrgID, name))
}

func (s *Store) GetProject(ctx context.Context, id string) (*Project, error) {
	return scanProject(s.pool.QueryRow(ctx, `SELECT `+projectColumns+` FROM projects WHERE id = $1`, id))
}

func (s *Store) ListProjects(ctx context.Context, ownerOrgID string, p Page) ([]*Project, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+projectColumns+` FROM projects WHERE owner_org_id = $1 ORDER BY created_at, id`+p.sql(), ownerOrgID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	projects := []*Project{}
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		projects = append(projects, p)
	}
	return projects, mapErr(rows.Err())
}

func (s *Store) DeleteProject(ctx context.Context, id string) error {
	return s.execOne(ctx, `DELETE FROM projects WHERE id = $1`, id)
}

// --- roles ------------------------------------------------------------------

func (s *Store) AddRole(ctx context.Context, projectID string, r Role) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO project_roles (project_id, key, display_name) VALUES ($1, $2, $3)`,
		projectID, r.Key, r.DisplayName)
	return mapErr(err)
}

func (s *Store) ListRoles(ctx context.Context, projectID string) ([]Role, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT key, display_name FROM project_roles WHERE project_id = $1 ORDER BY key`, projectID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	roles := []Role{}
	for rows.Next() {
		var r Role
		if err := rows.Scan(&r.Key, &r.DisplayName); err != nil {
			return nil, mapErr(err)
		}
		roles = append(roles, r)
	}
	return roles, mapErr(rows.Err())
}

// DeleteRole removes a role and strips it from every project and user grant.
func (s *Store) DeleteRole(ctx context.Context, projectID, key string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM project_roles WHERE project_id = $1 AND key = $2`, projectID, key)
		if err != nil {
			return mapErr(err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if _, err := tx.Exec(ctx,
			`UPDATE project_grants SET role_keys = array_remove(role_keys, $2) WHERE project_id = $1`,
			projectID, key); err != nil {
			return mapErr(err)
		}
		_, err = tx.Exec(ctx,
			`UPDATE user_grants SET role_keys = array_remove(role_keys, $2) WHERE project_id = $1`,
			projectID, key)
		return mapErr(err)
	})
}

// --- access resolution --------------------------------------------------------

// AvailableRoles returns the role keys an org may hand out for a project.
// The owner org gets every role; other orgs get the roles of their project grant.
// ok is false when the org has no access to the project at all.
func (s *Store) AvailableRoles(ctx context.Context, projectID, orgID string) (roles []string, ok bool, err error) {
	p, err := s.GetProject(ctx, projectID)
	if err != nil {
		return nil, false, err
	}
	if p.OwnerOrgID == orgID {
		all, err := s.ListRoles(ctx, projectID)
		if err != nil {
			return nil, false, err
		}
		for _, r := range all {
			roles = append(roles, r.Key)
		}
		return roles, true, nil
	}
	err = s.pool.QueryRow(ctx,
		`SELECT role_keys FROM project_grants WHERE project_id = $1 AND granted_org_id = $2`,
		projectID, orgID).Scan(&roles)
	if err = mapErr(err); err == ErrNotFound {
		return nil, false, nil
	}
	return roles, err == nil, err
}

// EffectiveRoles returns the user's roles for a project, limited to what the
// user's org is currently allowed to hand out.
func (s *Store) EffectiveRoles(ctx context.Context, user *User, projectID string) ([]string, error) {
	available, ok, err := s.AvailableRoles(ctx, projectID, user.OrgID)
	if err != nil || !ok {
		return []string{}, err
	}
	var assigned []string
	err = s.pool.QueryRow(ctx,
		`SELECT role_keys FROM user_grants WHERE user_id = $1 AND project_id = $2`,
		user.ID, projectID).Scan(&assigned)
	if err = mapErr(err); err == ErrNotFound {
		return []string{}, nil
	} else if err != nil {
		return nil, err
	}
	roles := []string{}
	for _, r := range assigned {
		if slices.Contains(available, r) {
			roles = append(roles, r)
		}
	}
	return roles, nil
}

func subset(keys, allowed []string) bool {
	for _, k := range keys {
		if !slices.Contains(allowed, k) {
			return false
		}
	}
	return true
}

// --- project grants -------------------------------------------------------------

const projectGrantColumns = `id, project_id, granted_org_id, role_keys, created_at`

func scanProjectGrant(row interface{ Scan(...any) error }) (*ProjectGrant, error) {
	var g ProjectGrant
	if err := row.Scan(&g.ID, &g.ProjectID, &g.GrantedOrgID, &g.RoleKeys, &g.CreatedAt); err != nil {
		return nil, mapErr(err)
	}
	return &g, nil
}

func (s *Store) CreateProjectGrant(ctx context.Context, projectID, orgID string, roleKeys []string) (*ProjectGrant, error) {
	p, err := s.GetProject(ctx, projectID)
	if err != nil {
		return nil, err
	}
	if p.OwnerOrgID == orgID {
		return nil, ErrConflict // the owner org already has full access
	}
	if err := s.checkRolesDefined(ctx, projectID, roleKeys); err != nil {
		return nil, err
	}
	return scanProjectGrant(s.pool.QueryRow(ctx, `
		INSERT INTO project_grants (id, project_id, granted_org_id, role_keys)
		VALUES ($1, $2, $3, $4) RETURNING `+projectGrantColumns,
		uuid.NewString(), projectID, orgID, roleKeys))
}

func (s *Store) GetProjectGrant(ctx context.Context, id string) (*ProjectGrant, error) {
	return scanProjectGrant(s.pool.QueryRow(ctx,
		`SELECT `+projectGrantColumns+` FROM project_grants WHERE id = $1`, id))
}

// ListProjectGrants lists grants of a project (projectID set) or to an org (orgID set).
func (s *Store) ListProjectGrants(ctx context.Context, projectID, orgID string, p Page) ([]*ProjectGrant, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+projectGrantColumns+` FROM project_grants
		WHERE ($1 = '' OR project_id::text = $1) AND ($2 = '' OR granted_org_id::text = $2)
		ORDER BY created_at, id`+p.sql(), projectID, orgID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	grants := []*ProjectGrant{}
	for rows.Next() {
		g, err := scanProjectGrant(rows)
		if err != nil {
			return nil, err
		}
		grants = append(grants, g)
	}
	return grants, mapErr(rows.Err())
}

// UpdateProjectGrant replaces the granted roles and strips removed roles from
// the user grants of that org's users.
func (s *Store) UpdateProjectGrant(ctx context.Context, id string, roleKeys []string) (*ProjectGrant, error) {
	g, err := s.GetProjectGrant(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.checkRolesDefined(ctx, g.ProjectID, roleKeys); err != nil {
		return nil, err
	}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE project_grants SET role_keys = $2 WHERE id = $1`, id, roleKeys); err != nil {
			return mapErr(err)
		}
		_, err := tx.Exec(ctx, `
			UPDATE user_grants ug SET role_keys = ARRAY(
				SELECT unnest(ug.role_keys) INTERSECT SELECT unnest($3::text[]))
			FROM users u
			WHERE ug.user_id = u.id AND ug.project_id = $1 AND u.org_id = $2`,
			g.ProjectID, g.GrantedOrgID, roleKeys)
		return mapErr(err)
	})
	if err != nil {
		return nil, err
	}
	return s.GetProjectGrant(ctx, id)
}

// DeleteProjectGrant revokes an org's access, including its users' grants.
func (s *Store) DeleteProjectGrant(ctx context.Context, id string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var projectID, orgID string
		err := tx.QueryRow(ctx,
			`DELETE FROM project_grants WHERE id = $1 RETURNING project_id, granted_org_id`, id,
		).Scan(&projectID, &orgID)
		if err != nil {
			return mapErr(err)
		}
		_, err = tx.Exec(ctx, `
			DELETE FROM user_grants ug USING users u
			WHERE ug.user_id = u.id AND ug.project_id = $1 AND u.org_id = $2`, projectID, orgID)
		return mapErr(err)
	})
}

func (s *Store) checkRolesDefined(ctx context.Context, projectID string, keys []string) error {
	roles, err := s.ListRoles(ctx, projectID)
	if err != nil {
		return err
	}
	defined := make([]string, 0, len(roles))
	for _, r := range roles {
		defined = append(defined, r.Key)
	}
	if !subset(keys, defined) {
		return ErrInvalidRole
	}
	return nil
}

// --- user grants ------------------------------------------------------------------

const userGrantColumns = `id, user_id, project_id, role_keys, created_at`

func scanUserGrant(row interface{ Scan(...any) error }) (*UserGrant, error) {
	var g UserGrant
	if err := row.Scan(&g.ID, &g.UserID, &g.ProjectID, &g.RoleKeys, &g.CreatedAt); err != nil {
		return nil, mapErr(err)
	}
	return &g, nil
}

// CreateUserGrant assigns roles; they must be within what the user's org may hand out.
func (s *Store) CreateUserGrant(ctx context.Context, user *User, projectID string, roleKeys []string) (*UserGrant, error) {
	available, ok, err := s.AvailableRoles(ctx, projectID, user.OrgID)
	if err != nil {
		return nil, err
	}
	if !ok || !subset(roleKeys, available) {
		return nil, ErrInvalidRole
	}
	return scanUserGrant(s.pool.QueryRow(ctx, `
		INSERT INTO user_grants (id, user_id, project_id, role_keys)
		VALUES ($1, $2, $3, $4) RETURNING `+userGrantColumns,
		uuid.NewString(), user.ID, projectID, roleKeys))
}

func (s *Store) GetUserGrant(ctx context.Context, id string) (*UserGrant, error) {
	return scanUserGrant(s.pool.QueryRow(ctx, `SELECT `+userGrantColumns+` FROM user_grants WHERE id = $1`, id))
}

func (s *Store) UpdateUserGrant(ctx context.Context, user *User, id string, roleKeys []string) (*UserGrant, error) {
	g, err := s.GetUserGrant(ctx, id)
	if err != nil {
		return nil, err
	}
	available, ok, err := s.AvailableRoles(ctx, g.ProjectID, user.OrgID)
	if err != nil {
		return nil, err
	}
	if !ok || !subset(roleKeys, available) {
		return nil, ErrInvalidRole
	}
	return scanUserGrant(s.pool.QueryRow(ctx,
		`UPDATE user_grants SET role_keys = $2 WHERE id = $1 RETURNING `+userGrantColumns, id, roleKeys))
}

func (s *Store) ListUserGrants(ctx context.Context, userID string, p Page) ([]*UserGrant, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+userGrantColumns+` FROM user_grants WHERE user_id = $1 ORDER BY created_at, id`+p.sql(), userID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	grants := []*UserGrant{}
	for rows.Next() {
		g, err := scanUserGrant(rows)
		if err != nil {
			return nil, err
		}
		grants = append(grants, g)
	}
	return grants, mapErr(rows.Err())
}

func (s *Store) DeleteUserGrant(ctx context.Context, id string) error {
	return s.execOne(ctx, `DELETE FROM user_grants WHERE id = $1`, id)
}
