-- Add support for TOTP (Time-based One-Time Password) 2FA

-- Add has_totp column to users table to track 2FA enrollment
ALTER TABLE users ADD COLUMN IF NOT EXISTS has_totp BOOLEAN NOT NULL DEFAULT FALSE;

-- Create table for storing TOTP secrets
CREATE TABLE IF NOT EXISTS user_totp_secrets (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret TEXT NOT NULL,
    confirmed_at TIMESTAMptz,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create table for storing recovery codes
CREATE TABLE IF NOT EXISTS user_recovery_codes (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, code_hash)
);

-- Add indexes for performance
CREATE INDEX IF NOT EXISTS idx_user_totp_secrets_user_id ON user_totp_secrets(user_id);
CREATE INDEX IF NOT EXISTS idx_user_recovery_codes_user_id ON user_recovery_codes(user_id) WHERE used_at IS NULL;

-- Add comments describing the tables
COMMENT ON TABLE user_totp_secrets IS 'Stores TOTP secrets for users who have enabled 2FA';
COMMENT ON TABLE user_recovery_codes IS 'Stores hashed recovery codes for users with 2FA enabled';
