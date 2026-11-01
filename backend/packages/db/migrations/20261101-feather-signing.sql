-- Separate exportable client identity. Server distribution-key/bootstrap readers are unchanged.
CREATE TABLE feather_signing_identities (
  id text PRIMARY KEY,
  connection_id text NOT NULL REFERENCES connections (id),
  owner_id text NOT NULL REFERENCES users (id),
  generation integer NOT NULL,
  revision integer NOT NULL,
  state text NOT NULL CHECK (
    state IN (
      'pending',
      'submitted',
      'unknown',
      'ready',
      'action_required',
      'revoking',
      'revoked',
      'retired'
    )
  ),
  secret_ref text REFERENCES secrets (id),
  csr text,
  spki_sha256 text,
  certificate_id text,
  certificate_pem text,
  certificate_sha256 text,
  expires_at bigint,
  reason text,
  lease_token text,
  lease_until bigint NOT NULL DEFAULT 0,
  created_at bigint NOT NULL,
  UNIQUE (connection_id, generation, revision)
);

CREATE UNIQUE INDEX feather_current_identity ON feather_signing_identities (connection_id, generation)
WHERE
  state <> 'retired';

CREATE TABLE feather_profile_operations (
  id text PRIMARY KEY,
  owner_id text NOT NULL REFERENCES users (id),
  identity_id text NOT NULL REFERENCES feather_signing_identities (id),
  binding jsonb NOT NULL,
  request jsonb NOT NULL,
  fingerprint text NOT NULL,
  state text NOT NULL CHECK (
    state IN ('pending', 'ready', 'action_required', 'retired')
  ),
  resources jsonb NOT NULL DEFAULT '{}'::jsonb,
  result jsonb,
  reason text,
  lease_token text,
  lease_until bigint NOT NULL DEFAULT 0,
  created_at bigint NOT NULL,
  UNIQUE (owner_id, identity_id, fingerprint)
);
