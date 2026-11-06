-- Add support for OIDC and external identities

-- Make password_hash and password_changed_at nullable for users with external identities
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
ALTER TABLE users ALTER COLUMN password_changed_at DROP NOT NULL;

-- Create table for external identities
CREATE TABLE external_identities (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    external_id TEXT NOT NULL,
    email TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (provider, external_id)
);

-- Create index for faster lookups by user_id
CREATE INDEX idx_external_identities_user_id ON external_identities(user_id);

-- Add comment describing the table purpose
COMMENT ON TABLE external_identities IS 'Stores external identity provider information for users, enabling OIDC login';
