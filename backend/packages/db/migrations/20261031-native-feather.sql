CREATE TABLE native_sessions (
  id text PRIMARY KEY,
  owner_id text NOT NULL REFERENCES users (id),
  access_hash text NOT NULL UNIQUE,
  verified_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  refresh_expires_at bigint NOT NULL,
  revoked_at bigint
);

CREATE INDEX native_sessions_owner ON native_sessions (owner_id);

CREATE TABLE native_refresh_tokens (
  token_hash text PRIMARY KEY,
  session_id text NOT NULL REFERENCES native_sessions (id) ON DELETE CASCADE,
  expires_at bigint NOT NULL,
  used_at bigint
);

CREATE INDEX native_refresh_session ON native_refresh_tokens (session_id);

CREATE TABLE native_auth_transactions (
  id_hash text PRIMARY KEY,
  state text NOT NULL,
  code_challenge text NOT NULL,
  redirect_uri text NOT NULL,
  owner_id text REFERENCES users (id),
  session_id text REFERENCES native_sessions (id) ON DELETE CASCADE,
  created_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  code_hash text UNIQUE,
  code_expires_at bigint,
  verified_at bigint,
  consumed_at bigint
);

CREATE INDEX native_auth_expiry ON native_auth_transactions (expires_at);
