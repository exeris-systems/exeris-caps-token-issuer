-- ADR-099: Layer 5 Domain Primitive token issuer & signing key persistence
CREATE TABLE IF NOT EXISTS exeris_signing_keys (
    kid VARCHAR(64) PRIMARY KEY,
    algorithm VARCHAR(32) NOT NULL,
    public_key_jwk TEXT NOT NULL,
    public_key_bytes BYTEA NOT NULL,
    private_key_pkcs8 BYTEA NOT NULL,
    state VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    retired_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_exeris_signing_keys_state
    ON exeris_signing_keys (state);

CREATE INDEX IF NOT EXISTS idx_exeris_signing_keys_expires_at
    ON exeris_signing_keys (expires_at);
