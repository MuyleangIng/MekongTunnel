-- Passkeys (WebAuthn credentials) for passwordless sign-in.
-- `credential` stores the full go-webauthn Credential record as JSON
-- (public key, sign counter, transports, flags, AAGUID).
CREATE TABLE IF NOT EXISTS passkeys (
    id           TEXT        PRIMARY KEY,               -- base64url credential ID
    user_id      UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT        NOT NULL DEFAULT 'Passkey',
    credential   JSONB       NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS passkeys_user_id_idx ON passkeys (user_id);
