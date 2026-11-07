-- Initial account and safety schema for PostgreSQL.
-- This migration is not wired into the current std-only server yet.
-- Do not add date of birth or self-declared age as an age-verification mechanism.

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL,
    username_normalized TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'locked', 'deleted')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT users_username_length CHECK (char_length(username) BETWEEN 3 AND 24),
    CONSTRAINT users_username_normalized_lower CHECK (username_normalized = lower(username_normalized)),
    CONSTRAINT users_username_normalized_format CHECK (username_normalized ~ '^[a-z0-9_]+$'),
    CONSTRAINT users_password_hash_nonempty CHECK (length(password_hash) > 0)
);

CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT sessions_token_hash_sha256 CHECK (octet_length(token_hash) = 32),
    CONSTRAINT sessions_expiry_after_creation CHECK (expires_at > created_at),
    CONSTRAINT sessions_revocation_after_creation CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);
CREATE INDEX sessions_user_expiry_idx ON sessions (user_id, expires_at);
CREATE INDEX sessions_active_expiry_idx ON sessions (expires_at) WHERE revoked_at IS NULL;

CREATE TABLE profiles (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    display_name TEXT,
    avatar_key TEXT,
    locale TEXT NOT NULL DEFAULT 'ru',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT profiles_display_name_length CHECK (display_name IS NULL OR char_length(display_name) <= 40),
    CONSTRAINT profiles_avatar_key_length CHECK (avatar_key IS NULL OR char_length(avatar_key) <= 120),
    CONSTRAINT profiles_locale_length CHECK (char_length(locale) BETWEEN 2 AND 16)
);

CREATE TABLE user_settings (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    theme_key TEXT NOT NULL DEFAULT 'ocean',
    sound_enabled BOOLEAN NOT NULL DEFAULT false,
    compact_mode BOOLEAN NOT NULL DEFAULT false,
    preferences JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT user_settings_theme_length CHECK (char_length(theme_key) BETWEEN 1 AND 32),
    CONSTRAINT user_settings_preferences_object CHECK (jsonb_typeof(preferences) = 'object')
);

CREATE TABLE blocks (
    blocker_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    blocked_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (blocker_user_id, blocked_user_id),
    CONSTRAINT blocks_no_self_block CHECK (blocker_user_id <> blocked_user_id)
);
CREATE INDEX blocks_reverse_lookup_idx ON blocks (blocked_user_id, blocker_user_id);

CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reporter_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reported_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    category TEXT NOT NULL
        CHECK (category IN ('harassment', 'spam', 'sexual_content', 'threats', 'other')),
    status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'reviewing', 'resolved', 'dismissed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_at TIMESTAMPTZ,
    CONSTRAINT reports_no_self_report CHECK (reporter_user_id <> reported_user_id)
);
CREATE INDEX reports_queue_idx ON reports (status, created_at);

CREATE TABLE moderation_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action TEXT NOT NULL CHECK (action IN ('warning', 'temporary_lock', 'permanent_lock', 'restriction_lifted')),
    reason_code TEXT NOT NULL,
    starts_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ends_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT moderation_reason_length CHECK (char_length(reason_code) BETWEEN 1 AND 64),
    CONSTRAINT moderation_action_period CHECK (ends_at IS NULL OR ends_at > starts_at)
);
CREATE INDEX moderation_user_history_idx ON moderation_actions (user_id, created_at DESC);
