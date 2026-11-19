#!/usr/bin/env bash
# CRYPTO-05 D3 restore/PITR operational demo.
#
# Proves, end to end against real databases and a real pg_dump/restore, that a
# PostgreSQL restore to a point BEFORE a signing-key revocation cannot resurrect
# the key: the independent revocation-epoch authority is unaffected by the IAM
# restore, reconciliation re-applies the revocation, and when the authority is
# unreachable the signing gate fails closed.
#
# Requires: docker, go (with the project toolchain). Creates and removes a
# disposable PostgreSQL container; touches nothing else. Not wired into CI.
#
# Usage: scripts/d3_restore_demo.sh
set -u

CONTAINER=iam-d3demo
PORT=55440
DUMP="${TMPDIR:-/tmp}/iam-d3demo-pre.sql"
export IAM_DATABASE_URL="postgres://iam:iam@localhost:${PORT}/iam?sslmode=disable"
export IAM_REVOCATION_AUTHORITY_URL="postgres://iam:iam@localhost:${PORT}/revauth?sslmode=disable"
BAD_AUTHORITY="postgres://iam:iam@localhost:1/revauth?sslmode=disable"

pass(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; }
die(){  printf '  \033[31mFAIL\033[0m %s\n' "$1"; cleanup; exit 1; }
step(){ printf '\n== %s\n' "$1"; }

cleanup(){ docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; rm -f "$DUMP" 2>/dev/null || true; }

helper(){ go run -tags demo ./scripts/d3demo "$@"; } # inherits exported URLs
is_suppressed(){ helper listed "$1" 2>/dev/null | grep -q '^SUPPRESSED'; }
is_listed(){ helper listed "$1" 2>/dev/null | grep -q '^LISTED'; }

step "Start disposable PostgreSQL with two independent databases (iam, revauth)"
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" -e POSTGRES_USER=iam -e POSTGRES_PASSWORD=iam -e POSTGRES_DB=iam -p "${PORT}:5432" postgres:16-alpine >/dev/null || die "docker run"
for i in $(seq 1 30); do docker exec "$CONTAINER" pg_isready -U iam >/dev/null 2>&1 && break; sleep 1; done
docker exec "$CONTAINER" createdb -U iam revauth >/dev/null 2>&1 || die "create revauth db"
pass "databases up"

step "Setup: migrate and insert a signing key"
KEY="$(helper setup)" || die "setup"
KEY="$(printf '%s' "$KEY" | tr -d '[:space:]')"
[ -n "$KEY" ] || die "no key id"
pass "key $KEY created and published"

step "Snapshot the IAM database BEFORE revocation (this is the PITR target)"
docker exec "$CONTAINER" pg_dump -U iam -d iam > "$DUMP" || die "pg_dump"
[ -s "$DUMP" ] || die "empty dump"
pass "pre-revocation snapshot captured"

step "Revoke the key (authority-first), then confirm it is suppressed"
helper revoke "$KEY" >/dev/null || die "revoke"
is_suppressed "$KEY" || die "key still published after revocation"
pass "key suppressed after revocation"

step "RESTORE the IAM database to the pre-revocation snapshot (real pg_dump restore)"
docker exec "$CONTAINER" dropdb --force -U iam iam >/dev/null 2>&1 || die "dropdb"
docker exec "$CONTAINER" createdb -U iam iam >/dev/null 2>&1 || die "createdb"
docker exec -i "$CONTAINER" psql -q -U iam -d iam < "$DUMP" >/dev/null 2>&1 || die "restore"
# The restored database has the key active, no tombstone, marker rewound.
is_listed "$KEY" || die "restore did not resurrect the key (demo precondition)"
pass "restore resurrected the key locally (the threat D3 must defeat)"

step "Reconcile against the independent authority (still ahead): gate opens, key re-suppressed"
helper reconcile || die "reconcile did not open the gate"
is_suppressed "$KEY" || die "key still published after reconciliation"
pass "reconciliation re-applied the revocation; key stays dead"

step "Authority unreachable after a restore: signing gate must fail closed"
IAM_REVOCATION_AUTHORITY_URL="$BAD_AUTHORITY" helper failclosed || die "gate did not fail closed with authority down"
pass "gate fails closed when the authority cannot be reached"

cleanup
printf '\n\033[32mD3 operational demo PASSED\033[0m\n'
