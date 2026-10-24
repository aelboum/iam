package store

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"
)

// AuditEvent is one entry of the security audit trail.
type AuditEvent struct {
	ID     int64          `json:"id"`
	At     time.Time      `json:"at"`
	OrgID  *string        `json:"org_id"`
	Actor  string         `json:"actor"`
	Action string         `json:"action"`
	Target string         `json:"target"`
	IP     string         `json:"ip"`
	Detail map[string]any `json:"detail"`
}

// Audit records an event. Failures are logged, not returned, so auditing
// never breaks the operation being audited.
func (s *Store) Audit(ctx context.Context, e AuditEvent) {
	if e.Detail == nil {
		e.Detail = map[string]any{}
	}
	detail, _ := json.Marshal(e.Detail)
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO audit_events (org_id, actor, action, target, ip, detail)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		e.OrgID, e.Actor, e.Action, e.Target, e.IP, detail); err != nil {
		slog.ErrorContext(ctx, "audit write failed", "action", e.Action, "error", err)
	}
}

// PurgeAudit deletes audit events older than retention.
func (s *Store) PurgeAudit(ctx context.Context, retention time.Duration) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM audit_events WHERE at < now() - make_interval(secs => $1)`, retention.Seconds())
	return mapErr(err)
}

// ListAudit returns the newest events, for one org or (orgID nil) all of them.
func (s *Store) ListAudit(ctx context.Context, orgID *string, before int64, limit int) ([]*AuditEvent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, at, org_id, actor, action, target, ip, detail FROM audit_events
		WHERE ($1::uuid IS NULL OR org_id = $1) AND ($2 = 0 OR id < $2)
		ORDER BY id DESC LIMIT $3`, orgID, before, limit)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	events := []*AuditEvent{}
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(&e.ID, &e.At, &e.OrgID, &e.Actor, &e.Action, &e.Target, &e.IP, &e.Detail); err != nil {
			return nil, mapErr(err)
		}
		events = append(events, &e)
	}
	return events, mapErr(rows.Err())
}
