-- CRYPTO-05 D3: restore/PITR revocation protection — local reconciliation marker.
--
-- Records the highest revocation epoch (from the independent revocation-epoch
-- authority, see internal/revepoch) that this IAM database has been reconciled
-- against. On startup and recovery the engine compares the authority's current
-- epoch with this marker; if the authority is ahead (as it is after a restore of
-- IAM PostgreSQL to a point before a revocation), the engine re-applies the
-- missing revocations and only then advances this marker. The signing gate stays
-- closed until reconciled_epoch >= the authority's current epoch.
--
-- Additive and backward compatible: a single row, created here, defaulting to
-- epoch 0 (nothing reconciled yet). This table lives in IAM PostgreSQL and is
-- itself restored by a PITR; that is expected — after a restore the marker may be
-- stale (low), which is exactly what makes the gate fail closed until the engine
-- reconciles against the independent authority.
CREATE TABLE revocation_reconciliation (
    id               boolean     PRIMARY KEY DEFAULT true CHECK (id),
    reconciled_epoch bigint      NOT NULL DEFAULT 0,
    reconciled_at    timestamptz NOT NULL DEFAULT now()
);

-- The single row. ON CONFLICT keeps the migration replay-safe.
INSERT INTO revocation_reconciliation (id) VALUES (true) ON CONFLICT (id) DO NOTHING;
