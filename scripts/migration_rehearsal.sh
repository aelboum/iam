#!/usr/bin/env bash
# Repeatable migration and backup/restore rehearsal for the IAM engine.
#
# This script exercises, against disposable and fully isolated Postgres
# containers, the three recovery-relevant properties documented in
# docs/DEPLOYMENT.md and tracked by workstream WS4 of docs/ROADMAP.md:
#
#   A. FRESH INSTALL   - a brand-new database has every migration applied, in
#                        order, and the engine becomes reachable afterwards.
#   B. BACKUP+RESTORE  - a pg_dump of a populated database restores onto a
#                        SEPARATE, isolated target with identical schema-
#                        migration state and the data intact, and a second
#                        engine run against the restored target applies zero
#                        further migrations (idempotent / consistent).
#   C. UPGRADE PATH    - a database left at the pre-0007 state (only
#                        0001..0006 applied) is upgraded by the engine, which
#                        applies exactly 0007, and a generic OIDC provider row
#                        that pre-dates 0007 survives as provider_type='oidc'
#                        with an empty tenant.
#
# Everything it creates is named with a unique run id and removed on exit, so
# it never touches a developer's running stack or any other container. It makes
# no network calls off the host and commits no secrets (ephemeral keys only).
#
# Requirements: Docker, and an engine image (default: iam-iam:latest; override
# with IAM_REHEARSAL_IMAGE). It changes nothing in the repository or on any
# existing database. Exit status is 0 only if every assertion passed.
#
# Usage:
#   scripts/migration_rehearsal.sh
#   IAM_REHEARSAL_IMAGE=iam-iam:latest scripts/migration_rehearsal.sh
set -euo pipefail

IMAGE="${IAM_REHEARSAL_IMAGE:-iam-iam:latest}"
PG_IMAGE="${IAM_REHEARSAL_PG_IMAGE:-postgres:17-alpine}"
RUN="rehearsal-$(date +%s)-$$"
NET="iam-${RUN}-net"
MIG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../internal/db/migrations" && pwd)"
WORK="$(mktemp -d)"
RESOURCES=()
FAILED=0

log()  { printf '\n=== %s ===\n' "$*"; }
pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; FAILED=1; }

cleanup() {
  log "cleanup"
  # Containers are started inside $(...) subshells, so match by the run's
  # unique name prefix rather than a shared array (which a subshell cannot
  # append to in the parent).
  local ids
  ids="$(docker ps -aq --filter "name=iam-${RUN}-" 2>/dev/null)"
  [ -n "$ids" ] && docker rm -f $ids >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Ephemeral, never-persisted credentials for the engine runs.
rand_b64() { head -c "$1" /dev/urandom | base64 | tr -d '\n'; }
uuid() { python -c "import uuid;print(uuid.uuid4())"; }
MASTER_KEY="$(rand_b64 32)"
ADMIN_KEY="$(rand_b64 48 | tr -d '/+=' | cut -c1-40)"

# The engine stores schema_migrations.version as the embedded glob path,
# e.g. "migrations/0001_init.sql". Build the ordered list from the repo.
mapfile -t MIG_FILES < <(cd "$MIG_DIR" && ls -1 [0-9]*.sql | sort)
MIG_COUNT="${#MIG_FILES[@]}"

psql_q() { # psql_q <pg_container> <sql> -> single value, whitespace-trimmed
  docker exec -i "$1" psql -U iam -d iam -tAc "$2" 2>/dev/null | tr -d '[:space:]'
}

start_pg() { # start_pg <name> -> waits until ready
  local name="iam-${RUN}-$1"
  RESOURCES+=("$name")
  docker run -d --name "$name" --network "$NET" \
    -e POSTGRES_USER=iam -e POSTGRES_PASSWORD=iam -e POSTGRES_DB=iam \
    "$PG_IMAGE" >/dev/null
  for _ in $(seq 1 60); do
    if docker exec "$name" pg_isready -U iam -d iam >/dev/null 2>&1; then
      echo "$name"; return 0
    fi
    sleep 1
  done
  echo "postgres $name did not become ready" >&2
  return 1
}

start_engine() { # start_engine <name> <pg_container> <host_port> -> waits until listening
  local name="iam-${RUN}-$1"
  RESOURCES+=("$name")
  docker run -d --name "$name" --network "$NET" -p "127.0.0.1:$3:8080" \
    -e IAM_ISSUER=http://localhost:8080 \
    -e IAM_DEV_MODE=true \
    -e IAM_DATABASE_URL="postgres://iam:iam@$2:5432/iam?sslmode=disable" \
    -e IAM_MASTER_KEY="$MASTER_KEY" \
    -e IAM_BOOTSTRAP_ADMIN_KEY="$ADMIN_KEY" \
    "$IMAGE" >/dev/null
  # Migrations run before the listener opens, so a reachable port proves the
  # migrate step completed. Any HTTP status (the engine 404s "/") counts.
  for _ in $(seq 1 60); do
    if curl -s -o /dev/null -m 2 "http://127.0.0.1:$3/"; then
      echo "$name"; return 0
    fi
    if [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" != "true" ]; then
      echo "engine $name exited during startup:" >&2
      docker logs "$name" 2>&1 | tail -20 >&2
      return 1
    fi
    sleep 1
  done
  echo "engine $name never started listening" >&2
  docker logs "$name" 2>&1 | tail -20 >&2
  return 1
}

docker network create "$NET" >/dev/null

############################################################################
log "A. FRESH INSTALL applies all $MIG_COUNT migrations in order"
############################################################################
PG_A="$(start_pg pg-fresh)"
ENG_A="$(start_engine eng-fresh "$PG_A" 18080)"
COUNT_A="$(psql_q "$PG_A" 'SELECT count(*) FROM schema_migrations;')"
[ "$COUNT_A" = "$MIG_COUNT" ] \
  && pass "schema_migrations has all $MIG_COUNT versions after fresh install" \
  || fail "expected $MIG_COUNT migrations, found ${COUNT_A:-0}"
# Each expected version is present.
for f in "${MIG_FILES[@]}"; do
  present="$(psql_q "$PG_A" "SELECT count(*) FROM schema_migrations WHERE version='migrations/$f';")"
  [ "$present" = "1" ] || fail "migration migrations/$f not recorded"
done
pass "engine reachable after fresh install (migrate step completed before listen)"
# Seed data to be preserved across backup/restore.
ORG_ID="$(uuid)"
docker exec "$PG_A" psql -U iam -d iam -q -c \
  "INSERT INTO orgs (id,name,slug) VALUES ('$ORG_ID','Rehearsal Org','rehearsal-org');" >/dev/null
SEEDED_A="$(psql_q "$PG_A" "SELECT count(*) FROM orgs WHERE id='$ORG_ID';")"
[ "$SEEDED_A" = "1" ] && pass "seeded one org row ($ORG_ID)" || fail "could not seed org row"

############################################################################
log "B. BACKUP then RESTORE onto a SEPARATE isolated target"
############################################################################
docker exec "$PG_A" pg_dump -U iam -d iam --clean --if-exists > "$WORK/backup.sql"
DUMP_BYTES="$(wc -c < "$WORK/backup.sql" | tr -d '[:space:]')"
[ "${DUMP_BYTES:-0}" -gt 0 ] && pass "pg_dump produced a non-empty backup ($DUMP_BYTES bytes)" || fail "pg_dump produced an empty backup"
# Restore to a fresh, separate database (the "isolated target first" rule).
PG_B="$(start_pg pg-restore)"
docker exec -i "$PG_B" psql -U iam -d iam -q < "$WORK/backup.sql" >/dev/null 2>&1 || true
COUNT_B="$(psql_q "$PG_B" 'SELECT count(*) FROM schema_migrations;')"
[ "$COUNT_B" = "$MIG_COUNT" ] \
  && pass "restored target has all $MIG_COUNT migration versions" \
  || fail "restored target has ${COUNT_B:-0} migration versions, expected $MIG_COUNT"
ORG_B="$(psql_q "$PG_B" "SELECT count(*) FROM orgs WHERE id='$ORG_ID';")"
[ "$ORG_B" = "1" ] && pass "seeded org row present on restored target" || fail "seeded org row missing after restore"
# Validate the restored target by pointing a fresh engine at it: it must apply
# zero new migrations and become reachable.
ENG_B="$(start_engine eng-restore "$PG_B" 18081)"
COUNT_B2="$(psql_q "$PG_B" 'SELECT count(*) FROM schema_migrations;')"
[ "$COUNT_B2" = "$MIG_COUNT" ] \
  && pass "engine against restored target applied zero further migrations (still $MIG_COUNT)" \
  || fail "migration count changed on restored target: $COUNT_B2"

############################################################################
log "C. UPGRADE PATH: pre-0007 database upgraded by the engine"
############################################################################
PG_C="$(start_pg pg-upgrade)"
# Apply only 0001..0006 by hand and record them, leaving 0007 pending.
docker exec "$PG_C" psql -U iam -d iam -q -c \
  "CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());" >/dev/null
for f in "${MIG_FILES[@]}"; do
  case "$f" in
    0007_*) continue ;;
  esac
  docker exec -i "$PG_C" psql -U iam -d iam -q -v ON_ERROR_STOP=1 < "$MIG_DIR/$f" >/dev/null
  docker exec "$PG_C" psql -U iam -d iam -q -c \
    "INSERT INTO schema_migrations (version) VALUES ('migrations/$f');" >/dev/null
done
PRE="$(psql_q "$PG_C" 'SELECT count(*) FROM schema_migrations;')"
EXPECT_PRE=$((MIG_COUNT - 1))
[ "$PRE" = "$EXPECT_PRE" ] \
  && pass "pre-upgrade database at $PRE migrations (0007 pending)" \
  || fail "pre-upgrade database has $PRE migrations, expected $EXPECT_PRE"
# Insert a generic OIDC provider the pre-0007 way (no provider_type column yet).
LEGACY_ORG="$(uuid)"
IDP_ID="$(uuid)"
docker exec "$PG_C" psql -U iam -d iam -q -v ON_ERROR_STOP=1 \
  -c "INSERT INTO orgs (id,name,slug) VALUES ('$LEGACY_ORG','Legacy Org','legacy-org');" \
  -c "INSERT INTO identity_providers (id,org_id,name,issuer,client_id,client_secret_enc) VALUES ('$IDP_ID','$LEGACY_ORG','Legacy OIDC','https://issuer.example','legacy-client','\\x');" >/dev/null
SEEDED_C="$(psql_q "$PG_C" "SELECT count(*) FROM identity_providers WHERE id='$IDP_ID';")"
[ "$SEEDED_C" = "1" ] && pass "seeded a pre-0007 generic OIDC provider ($IDP_ID)" || fail "could not seed legacy provider"
# Upgrade by starting the engine; it must apply exactly 0007.
ENG_C="$(start_engine eng-upgrade "$PG_C" 18082)"
POST="$(psql_q "$PG_C" 'SELECT count(*) FROM schema_migrations;')"
[ "$POST" = "$MIG_COUNT" ] \
  && pass "engine upgraded database to all $MIG_COUNT migrations" \
  || fail "post-upgrade migration count is $POST, expected $MIG_COUNT"
HAS_0007="$(psql_q "$PG_C" "SELECT count(*) FROM schema_migrations WHERE version='migrations/0007_social_login.sql';")"
[ "$HAS_0007" = "1" ] && pass "0007 recorded after upgrade" || fail "0007 not recorded after upgrade"
PTYPE="$(psql_q "$PG_C" "SELECT provider_type FROM identity_providers WHERE id='$IDP_ID';")"
PTENANT="$(psql_q "$PG_C" "SELECT tenant FROM identity_providers WHERE id='$IDP_ID';")"
[ "$PTYPE" = "oidc" ] \
  && pass "pre-existing provider defaulted to provider_type='oidc'" \
  || fail "pre-existing provider has provider_type='$PTYPE', expected 'oidc'"
[ -z "$PTENANT" ] \
  && pass "pre-existing provider has empty tenant" \
  || fail "pre-existing provider has tenant='$PTENANT', expected empty"

############################################################################
if [ "$FAILED" -eq 0 ]; then
  log "REHEARSAL RESULT: ALL_PASS"
else
  log "REHEARSAL RESULT: SOME_FAIL"
fi
############################################################################
exit "$FAILED"
