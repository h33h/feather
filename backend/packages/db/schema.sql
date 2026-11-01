-- Fresh personal installation only. No migration or legacy data import.
CREATE TABLE auth_limits (
  key text NOT NULL,
  window_start bigint NOT NULL,
  count integer NOT NULL,
  CONSTRAINT auth_limits_pkey PRIMARY KEY (key)
);

CREATE TABLE personal_state (
  id integer NOT NULL,
  CONSTRAINT personal_state_id_check CHECK ((id = 1)),
  CONSTRAINT personal_state_pkey PRIMARY KEY (id)
);

CREATE TABLE users (
  id text NOT NULL,
  created_at bigint NOT NULL,
  deleted_at bigint,
  public_profile_id text NOT NULL DEFAULT (
    'profile_'::text || replace((gen_random_uuid())::text, '-'::text, ''::text)
  ),
  login_name text NOT NULL,
  role text NOT NULL DEFAULT 'user'::text,
  blocked_at bigint,
  CONSTRAINT users_pkey PRIMARY KEY (id),
  CONSTRAINT users_role_check CHECK (role IN ('user', 'admin')),
  CONSTRAINT users_login_unique UNIQUE (login_name)
);

CREATE UNIQUE INDEX public_profile_id_unique ON public.users USING btree (public_profile_id);

CREATE TABLE audit (
  id text NOT NULL,
  owner_id text NOT NULL,
  event text NOT NULL,
  metadata jsonb NOT NULL,
  created_at bigint NOT NULL,
  CONSTRAINT audit_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES users (id),
  CONSTRAINT audit_pkey PRIMARY KEY (id)
);

CREATE TABLE collected_devices (
  id text NOT NULL,
  owner_id text NOT NULL,
  name text NOT NULL,
  udid text NOT NULL,
  udid_hash text NOT NULL,
  product text,
  os_version text,
  enrollment_verified_at bigint NOT NULL,
  enrollment_cms_sha256 text NOT NULL,
  created_at bigint NOT NULL,
  updated_at bigint NOT NULL,
  CONSTRAINT collected_devices_id_owner_id_key UNIQUE (id, owner_id),
  CONSTRAINT collected_devices_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE,
  CONSTRAINT collected_devices_owner_id_udid_hash_key UNIQUE (owner_id, udid_hash),
  CONSTRAINT collected_devices_pkey PRIMARY KEY (id)
);

CREATE TABLE connections (
  id text NOT NULL,
  owner_id text NOT NULL,
  team_id text NOT NULL,
  state text NOT NULL,
  generation integer NOT NULL DEFAULT 1,
  provider text NOT NULL DEFAULT 'asc'::text,
  issuer_id text,
  key_id text,
  secret_ref text,
  last_error text,
  CONSTRAINT connections_id_owner_id_key UNIQUE (id, owner_id),
  CONSTRAINT connections_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES users (id),
  CONSTRAINT connections_pkey PRIMARY KEY (id),
  CONSTRAINT connections_state_check CHECK (
    (
      state = ANY (
        ARRAY[
          'disconnected'::text,
          'validating'::text,
          'ready'::text,
          'action_required'::text
        ]
      )
    )
  ),
  CONSTRAINT connections_team_id_key UNIQUE (team_id)
);

CREATE TABLE device_collection_challenges (
  id text NOT NULL,
  owner_id text NOT NULL,
  token_hash text NOT NULL,
  session_hash text NOT NULL,
  expires_at bigint NOT NULL,
  consumed_at bigint,
  profile_downloaded_at bigint,
  created_at bigint NOT NULL,
  CONSTRAINT device_collection_challenges_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE,
  CONSTRAINT device_collection_challenges_pkey PRIMARY KEY (id),
  CONSTRAINT device_collection_challenges_token_hash_key UNIQUE (token_hash)
);

CREATE INDEX active_device_collection_challenges ON public.device_collection_challenges USING btree (owner_id, expires_at)
WHERE
  (consumed_at IS NULL);

CREATE TABLE identities (
  id text NOT NULL,
  owner_id text NOT NULL,
  connection_id text NOT NULL,
  secret_ref text NOT NULL,
  certificate_digest text NOT NULL,
  expires_at bigint NOT NULL,
  CONSTRAINT identities_connection_id_owner_id_fkey FOREIGN KEY (connection_id, owner_id) REFERENCES connections (id, owner_id),
  CONSTRAINT identities_id_owner_id_key UNIQUE (id, owner_id),
  CONSTRAINT identities_pkey PRIMARY KEY (id)
);

CREATE TABLE passkey_challenges (
  id text NOT NULL,
  challenge text NOT NULL,
  kind text NOT NULL,
  owner_id text,
  invite_hash text,
  session_hash text,
  expires_at bigint NOT NULL,
  consumed_at bigint,
  CONSTRAINT passkey_challenges_kind_check CHECK (
    (
      kind = ANY (
        ARRAY[
          'register'::text,
          'login'::text,
          'fresh'::text,
          'add'::text
        ]
      )
    )
  ),
  CONSTRAINT passkey_challenges_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES users (id),
  CONSTRAINT passkey_challenges_pkey PRIMARY KEY (id)
);

CREATE TABLE passkey_invites (
  token_hash text NOT NULL,
  owner_id text NOT NULL,
  expires_at bigint NOT NULL,
  consumed_at bigint,
  CONSTRAINT passkey_invites_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES users (id),
  CONSTRAINT passkey_invites_pkey PRIMARY KEY (token_hash)
);

CREATE TABLE passkeys (
  id text NOT NULL,
  owner_id text NOT NULL,
  public_key text NOT NULL,
  counter bigint NOT NULL,
  transports jsonb NOT NULL,
  created_at bigint NOT NULL,
  CONSTRAINT passkeys_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES users (id),
  CONSTRAINT passkeys_pkey PRIMARY KEY (id)
);

CREATE TABLE personal_objects (
  id text NOT NULL,
  owner_id text NOT NULL,
  kind text NOT NULL,
  object_key text,
  size bigint NOT NULL,
  state text NOT NULL,
  job_id text,
  lease_expires bigint NOT NULL,
  created_at bigint NOT NULL,
  CONSTRAINT personal_objects_job_id_key UNIQUE (job_id),
  CONSTRAINT personal_objects_kind_check CHECK (
    (
      kind = ANY (ARRAY['upload'::text, 'artifact'::text])
    )
  ),
  CONSTRAINT personal_objects_object_key_key UNIQUE (object_key),
  CONSTRAINT personal_objects_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES users (id),
  CONSTRAINT personal_objects_pkey PRIMARY KEY (id),
  CONSTRAINT personal_objects_size_check CHECK ((size >= 0)),
  CONSTRAINT personal_objects_state_check CHECK (
    (
      state = ANY (
        ARRAY[
          'reserved'::text,
          'writing'::text,
          'live'::text,
          'deleting'::text
        ]
      )
    )
  )
);

CREATE TABLE profiles (
  id text NOT NULL,
  owner_id text NOT NULL,
  connection_id text NOT NULL,
  identity_id text NOT NULL,
  bundle_id text NOT NULL,
  expires_at bigint NOT NULL,
  metadata jsonb NOT NULL,
  CONSTRAINT profiles_connection_id_owner_id_fkey FOREIGN KEY (connection_id, owner_id) REFERENCES connections (id, owner_id),
  CONSTRAINT profiles_id_owner_id_key UNIQUE (id, owner_id),
  CONSTRAINT profiles_identity_id_owner_id_fkey FOREIGN KEY (identity_id, owner_id) REFERENCES identities (id, owner_id),
  CONSTRAINT profiles_pkey PRIMARY KEY (id)
);

CREATE TABLE secrets (
  id text NOT NULL,
  owner_id text NOT NULL,
  connection_id text NOT NULL,
  purpose text NOT NULL,
  wrapped_key text NOT NULL,
  nonce text NOT NULL,
  ciphertext text NOT NULL,
  tag text NOT NULL,
  deleted_at bigint,
  generation integer NOT NULL DEFAULT 1,
  CONSTRAINT secrets_connection_id_owner_id_fkey FOREIGN KEY (connection_id, owner_id) REFERENCES connections (id, owner_id),
  CONSTRAINT secrets_id_owner_id_key UNIQUE (id, owner_id),
  CONSTRAINT secrets_pkey PRIMARY KEY (id)
);

CREATE TABLE sessions (
  token_hash text NOT NULL,
  owner_id text NOT NULL,
  csrf_hash text NOT NULL,
  verified_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  CONSTRAINT sessions_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES users (id),
  CONSTRAINT sessions_pkey PRIMARY KEY (token_hash)
);

CREATE TABLE sources (
  id text NOT NULL,
  owner_id text NOT NULL,
  name text NOT NULL,
  canonical_url text,
  kind text NOT NULL,
  state text NOT NULL,
  revision integer NOT NULL DEFAULT 0,
  feed jsonb,
  last_sync bigint,
  last_error text,
  refresh_failures integer NOT NULL DEFAULT 0,
  next_refresh_at bigint NOT NULL DEFAULT 0,
  refresh_lease_until bigint NOT NULL DEFAULT 0,
  refresh_token text,
  CONSTRAINT sources_id_owner_id_key UNIQUE (id, owner_id),
  CONSTRAINT sources_owner_id_canonical_url_key UNIQUE (owner_id, canonical_url),
  CONSTRAINT sources_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES users (id),
  CONSTRAINT sources_pkey PRIMARY KEY (id)
);

CREATE TABLE uploads (
  id text NOT NULL,
  owner_id text NOT NULL,
  name text NOT NULL,
  object_key text NOT NULL,
  size bigint NOT NULL,
  digest text NOT NULL,
  status text NOT NULL,
  metadata jsonb,
  provenance jsonb,
  created_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  delete_requested_at bigint,
  CONSTRAINT uploads_id_owner_id_key UNIQUE (id, owner_id),
  CONSTRAINT uploads_object_key_key UNIQUE (object_key),
  CONSTRAINT uploads_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES users (id),
  CONSTRAINT uploads_pkey PRIMARY KEY (id),
  CONSTRAINT uploads_size_check CHECK (
    (
      (size >= 0)
      AND (size <= 1073741824)
    )
  )
);

CREATE TABLE apple_access_grants (
  id text NOT NULL,
  connection_id text NOT NULL,
  connection_owner_id text NOT NULL,
  recipient_id text NOT NULL,
  connection_generation integer NOT NULL,
  generation integer NOT NULL DEFAULT 1,
  state text NOT NULL,
  created_at bigint NOT NULL,
  revoked_at bigint,
  CONSTRAINT apple_access_grants_check CHECK ((connection_owner_id <> recipient_id)),
  CONSTRAINT apple_access_grants_connection_id_connection_owner_id_fkey FOREIGN KEY (connection_id, connection_owner_id) REFERENCES connections (id, owner_id),
  CONSTRAINT apple_access_grants_connection_id_recipient_id_key UNIQUE (connection_id, recipient_id),
  CONSTRAINT apple_access_grants_pkey PRIMARY KEY (id),
  CONSTRAINT apple_access_grants_recipient_id_fkey FOREIGN KEY (recipient_id) REFERENCES users (id),
  CONSTRAINT apple_access_grants_state_check CHECK (state IN ('accepted', 'revoked')),
  CONSTRAINT apple_access_grants_binding_key UNIQUE (
    id,
    recipient_id,
    connection_id,
    connection_owner_id
  )
);

CREATE TABLE bootstrap_operations (
  owner_id text NOT NULL,
  connection_id text NOT NULL,
  generation integer NOT NULL,
  nonce text NOT NULL,
  expires_at bigint NOT NULL,
  identity jsonb,
  certificate_state text NOT NULL DEFAULT 'prepared'::text,
  certificate jsonb,
  CONSTRAINT bootstrap_operations_connection_id_owner_id_fkey FOREIGN KEY (connection_id, owner_id) REFERENCES connections (id, owner_id),
  CONSTRAINT bootstrap_operations_pkey PRIMARY KEY (owner_id, connection_id, generation)
);

CREATE TABLE bootstrap_secret_grants (
  secret_id text NOT NULL,
  owner_id text NOT NULL,
  connection_id text NOT NULL,
  generation integer NOT NULL,
  bootstrap_nonce text NOT NULL,
  bootstrap_expires_at bigint NOT NULL,
  grant_nonce text NOT NULL,
  audience text NOT NULL,
  instance_id text NOT NULL,
  purpose text NOT NULL,
  expires_at bigint NOT NULL,
  wrapped_key text NOT NULL,
  aad text NOT NULL,
  consumed boolean NOT NULL DEFAULT false,
  CONSTRAINT bootstrap_secret_grants_connection_id_owner_id_fkey FOREIGN KEY (connection_id, owner_id) REFERENCES connections (id, owner_id),
  CONSTRAINT bootstrap_secret_grants_grant_nonce_key UNIQUE (grant_nonce),
  CONSTRAINT bootstrap_secret_grants_owner_id_connection_id_generation_fkey FOREIGN KEY (owner_id, connection_id, generation) REFERENCES bootstrap_operations (owner_id, connection_id, generation),
  CONSTRAINT bootstrap_secret_grants_pkey PRIMARY KEY (secret_id),
  CONSTRAINT bootstrap_secret_grants_purpose_check CHECK (
    (
      purpose = ANY (ARRAY['p8'::text, 'distribution-key'::text])
    )
  )
);

CREATE TABLE device_challenges (
  id text NOT NULL,
  owner_id text NOT NULL,
  connection_id text NOT NULL,
  generation integer NOT NULL,
  token_hash text NOT NULL,
  expires_at bigint NOT NULL,
  consumed_at bigint,
  session_hash text,
  connection_owner_id text,
  access_grant_id text,
  access_grant_generation integer,
  CONSTRAINT device_challenges_access_grant_id_fkey FOREIGN KEY (access_grant_id) REFERENCES apple_access_grants (id),
  CONSTRAINT device_challenges_connection_principal_fkey FOREIGN KEY (connection_id, connection_owner_id) REFERENCES connections (id, owner_id),
  CONSTRAINT device_challenges_pkey PRIMARY KEY (id),
  CONSTRAINT device_challenges_token_hash_key UNIQUE (token_hash)
);

CREATE TABLE device_registration_operations (
  id text NOT NULL,
  connection_id text NOT NULL,
  connection_owner_id text NOT NULL,
  generation integer NOT NULL,
  udid_hash text NOT NULL,
  principal_id text NOT NULL,
  device_id text NOT NULL,
  access_grant_id text,
  access_grant_generation integer,
  state text NOT NULL,
  resource_id text,
  created_at bigint NOT NULL,
  CONSTRAINT device_registration_operation_connection_id_connection_own_fkey FOREIGN KEY (connection_id, connection_owner_id) REFERENCES connections (id, owner_id),
  CONSTRAINT device_registration_operation_connection_id_generation_udid_key UNIQUE (connection_id, generation, udid_hash),
  CONSTRAINT device_registration_operations_access_grant_id_fkey FOREIGN KEY (access_grant_id) REFERENCES apple_access_grants (id),
  CONSTRAINT device_registration_operations_pkey PRIMARY KEY (id),
  CONSTRAINT device_registration_operations_principal_id_fkey FOREIGN KEY (principal_id) REFERENCES users (id),
  CONSTRAINT device_registration_operations_state_check CHECK (
    (
      state = ANY (
        ARRAY[
          'submitted'::text,
          'unknown'::text,
          'complete'::text,
          'revoked'::text
        ]
      )
    )
  )
);

CREATE TABLE devices (
  id text NOT NULL,
  owner_id text NOT NULL,
  connection_id text NOT NULL,
  name text NOT NULL,
  status text NOT NULL,
  os_version text,
  selected boolean NOT NULL DEFAULT false,
  udid text,
  udid_hash text,
  apple_resource_id text,
  connection_generation integer,
  enrollment_verified_at bigint,
  enrollment_cms_sha256 text,
  os_version_source text,
  connection_owner_id text,
  access_grant_id text,
  access_grant_generation integer,
  CONSTRAINT devices_access_grant_id_fkey FOREIGN KEY (access_grant_id) REFERENCES apple_access_grants (id),
  CONSTRAINT devices_connection_principal_fkey FOREIGN KEY (connection_id, connection_owner_id) REFERENCES connections (id, owner_id),
  CONSTRAINT devices_id_owner_id_key UNIQUE (id, owner_id),
  CONSTRAINT devices_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES users (id),
  CONSTRAINT devices_pkey PRIMARY KEY (id),
  CONSTRAINT devices_status_check CHECK (
    (
      status = ANY (
        ARRAY[
          'collected'::text,
          'registering'::text,
          'apple_processing'::text,
          'certificate_required'::text,
          'ready'::text,
          'ineligible'::text,
          'disabled'::text,
          'locally_removed'::text
        ]
      )
    )
  )
);

CREATE UNIQUE INDEX selected_device_per_owner ON public.devices USING btree (owner_id)
WHERE
  selected;

CREATE UNIQUE INDEX owner_device_udid ON public.devices USING btree (owner_id, connection_id, udid_hash)
WHERE
  (udid_hash IS NOT NULL);

CREATE TABLE imports (
  id text NOT NULL,
  owner_id text NOT NULL,
  source_id text NOT NULL,
  release_id text NOT NULL,
  snapshot text NOT NULL,
  state text NOT NULL,
  upload_id text,
  created_at bigint NOT NULL,
  lease_expires bigint NOT NULL DEFAULT 0,
  attempt_token text,
  CONSTRAINT imports_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES users (id),
  CONSTRAINT imports_owner_id_source_id_release_id_snapshot_key UNIQUE (owner_id, source_id, release_id, snapshot),
  CONSTRAINT imports_pkey PRIMARY KEY (id),
  CONSTRAINT imports_source_id_owner_id_fkey FOREIGN KEY (source_id, owner_id) REFERENCES sources (id, owner_id),
  CONSTRAINT imports_upload_id_owner_id_fkey FOREIGN KEY (upload_id, owner_id) REFERENCES uploads (id, owner_id)
);

CREATE TABLE jobs (
  id text NOT NULL,
  owner_id text NOT NULL,
  upload_id text NOT NULL,
  device_id text,
  state text NOT NULL,
  reason text,
  idempotency_key text NOT NULL,
  request_digest text NOT NULL DEFAULT '',
  lease_token text,
  lease_expires bigint,
  attempts integer NOT NULL DEFAULT 0,
  created_at bigint NOT NULL,
  updated_at bigint NOT NULL,
  connection_id text,
  connection_generation integer,
  connection_owner_id text,
  access_grant_id text,
  access_grant_generation integer,
  display_snapshot jsonb,
  finished_at bigint,
  warnings jsonb NOT NULL DEFAULT '[]'::jsonb,
  next_attempt_at bigint NOT NULL DEFAULT 0,
  CONSTRAINT jobs_access_grant_id_fkey FOREIGN KEY (access_grant_id) REFERENCES apple_access_grants (id),
  CONSTRAINT jobs_device_id_owner_id_fkey FOREIGN KEY (device_id, owner_id) REFERENCES devices (id, owner_id),
  CONSTRAINT jobs_id_owner_id_key UNIQUE (id, owner_id),
  CONSTRAINT jobs_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES users (id),
  CONSTRAINT jobs_owner_id_idempotency_key_key UNIQUE (owner_id, idempotency_key),
  CONSTRAINT jobs_pkey PRIMARY KEY (id),
  CONSTRAINT jobs_upload_id_owner_id_fkey FOREIGN KEY (upload_id, owner_id) REFERENCES uploads (id, owner_id),
  CONSTRAINT jobs_state_check CHECK (
    state IN (
      'receiving',
      'queued',
      'analyzing',
      'provisioning',
      'signing',
      'verifying',
      'ready',
      'failed',
      'cancelled'
    )
  ),
  CONSTRAINT jobs_attempts_check CHECK (attempts BETWEEN 0 AND 2)
);

CREATE INDEX jobs_owner_history_page ON public.jobs USING btree (owner_id, created_at DESC, id DESC);

CREATE UNIQUE INDEX one_active_job_per_owner ON jobs (owner_id)
WHERE
  state IN (
    'receiving',
    'queued',
    'analyzing',
    'provisioning',
    'signing',
    'verifying'
  );

CREATE TABLE mappings (
  id text NOT NULL,
  connection_generation integer NOT NULL DEFAULT 1,
  owner_id text NOT NULL,
  connection_id text NOT NULL,
  original_id text NOT NULL,
  target_id text NOT NULL,
  connection_owner_id text,
  access_grant_id text,
  access_grant_generation integer,
  CONSTRAINT mappings_access_grant_id_fkey FOREIGN KEY (access_grant_id) REFERENCES apple_access_grants (id),
  CONSTRAINT mappings_connection_principal_fkey FOREIGN KEY (connection_id, connection_owner_id) REFERENCES connections (id, owner_id),
  CONSTRAINT mappings_owner_id_connection_id_original_id_key UNIQUE (owner_id, connection_id, original_id),
  CONSTRAINT mappings_pkey PRIMARY KEY (id)
);

CREATE UNIQUE INDEX mappings_principal_target ON public.mappings USING btree (owner_id, connection_id, target_id);

CREATE TABLE provisioning_operations (
  id text NOT NULL,
  owner_id text NOT NULL,
  connection_id text NOT NULL,
  generation integer NOT NULL,
  kind text NOT NULL,
  fingerprint text NOT NULL,
  state text NOT NULL,
  resource_id text,
  key_ref text,
  created_at bigint NOT NULL,
  CONSTRAINT provisioning_operations_connection_id_owner_id_fkey FOREIGN KEY (connection_id, owner_id) REFERENCES connections (id, owner_id),
  CONSTRAINT provisioning_operations_key_ref_owner_id_fkey FOREIGN KEY (key_ref, owner_id) REFERENCES secrets (id, owner_id),
  CONSTRAINT provisioning_operations_owner_id_connection_id_generation_k_key UNIQUE (
    owner_id,
    connection_id,
    generation,
    kind,
    fingerprint
  ),
  CONSTRAINT provisioning_operations_pkey PRIMARY KEY (id)
);

CREATE TABLE releases (
  id text NOT NULL,
  source_id text NOT NULL,
  owner_id text NOT NULL,
  snapshot text NOT NULL,
  metadata jsonb NOT NULL,
  CONSTRAINT releases_pkey PRIMARY KEY (id, source_id, owner_id),
  CONSTRAINT releases_source_id_owner_id_fkey FOREIGN KEY (source_id, owner_id) REFERENCES sources (id, owner_id)
);

CREATE TABLE secret_deletions (
  id text NOT NULL,
  owner_id text NOT NULL,
  secret_id text NOT NULL,
  created_at bigint NOT NULL,
  lease_token text,
  lease_expires bigint,
  attempts integer NOT NULL DEFAULT 0,
  completed_at bigint,
  CONSTRAINT secret_deletions_owner_id_secret_id_key UNIQUE (owner_id, secret_id),
  CONSTRAINT secret_deletions_pkey PRIMARY KEY (id),
  CONSTRAINT secret_deletions_secret_id_owner_id_fkey FOREIGN KEY (secret_id, owner_id) REFERENCES secrets (id, owner_id)
);

CREATE TABLE selections (
  owner_id text NOT NULL,
  source_id text NOT NULL,
  release_id text NOT NULL,
  snapshot text NOT NULL,
  CONSTRAINT selections_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES users (id),
  CONSTRAINT selections_pkey PRIMARY KEY (owner_id),
  CONSTRAINT selections_source_id_owner_id_fkey FOREIGN KEY (source_id, owner_id) REFERENCES sources (id, owner_id)
);

CREATE TABLE artifacts (
  id text NOT NULL,
  owner_id text NOT NULL,
  job_id text NOT NULL,
  connection_id text NOT NULL,
  device_id text NOT NULL,
  object_key text NOT NULL,
  digest text NOT NULL,
  metadata jsonb NOT NULL,
  valid_until bigint NOT NULL,
  created_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  verified boolean NOT NULL DEFAULT false,
  connection_owner_id text,
  access_grant_id text,
  access_grant_generation integer,
  ready_at bigint NOT NULL DEFAULT 0,
  CONSTRAINT artifacts_access_grant_id_fkey FOREIGN KEY (access_grant_id) REFERENCES apple_access_grants (id),
  CONSTRAINT artifacts_connection_principal_fkey FOREIGN KEY (connection_id, connection_owner_id) REFERENCES connections (id, owner_id),
  CONSTRAINT artifacts_device_id_owner_id_fkey FOREIGN KEY (device_id, owner_id) REFERENCES devices (id, owner_id),
  CONSTRAINT artifacts_id_owner_id_key UNIQUE (id, owner_id),
  CONSTRAINT artifacts_job_id_owner_id_fkey FOREIGN KEY (job_id, owner_id) REFERENCES jobs (id, owner_id),
  CONSTRAINT artifacts_object_key_key UNIQUE (object_key),
  CONSTRAINT artifacts_pkey PRIMARY KEY (id)
);

CREATE TABLE device_collection_checks (
  id text NOT NULL,
  collected_device_id text NOT NULL,
  owner_id text NOT NULL,
  connection_id text NOT NULL,
  connection_owner_id text NOT NULL,
  generation integer NOT NULL,
  access_grant_id text,
  access_grant_generation integer,
  device_id text,
  status text NOT NULL DEFAULT 'collected'::text,
  next_check_at bigint NOT NULL DEFAULT 0,
  lease_token text,
  lease_until bigint NOT NULL DEFAULT 0,
  failures integer NOT NULL DEFAULT 0,
  last_error text,
  last_checked_at bigint,
  CONSTRAINT device_collection_checks_access_grant_id_fkey FOREIGN KEY (access_grant_id) REFERENCES apple_access_grants (id),
  CONSTRAINT device_collection_checks_collected_device_id_connection_id_key UNIQUE (collected_device_id, connection_id),
  CONSTRAINT device_collection_checks_collected_device_id_owner_id_fkey FOREIGN KEY (collected_device_id, owner_id) REFERENCES collected_devices (id, owner_id) ON DELETE CASCADE,
  CONSTRAINT device_collection_checks_connection_id_connection_owner_id_fkey FOREIGN KEY (connection_id, connection_owner_id) REFERENCES connections (id, owner_id) ON DELETE CASCADE,
  CONSTRAINT device_collection_checks_device_id_owner_id_fkey FOREIGN KEY (device_id, owner_id) REFERENCES devices (id, owner_id),
  CONSTRAINT device_collection_checks_pkey PRIMARY KEY (id),
  CONSTRAINT device_collection_checks_status_check CHECK (
    (
      status = ANY (
        ARRAY[
          'collected'::text,
          'not_registered'::text,
          'registering'::text,
          'apple_processing'::text,
          'certificate_required'::text,
          'ready'::text,
          'ineligible'::text,
          'disabled'::text,
          'locally_removed'::text
        ]
      )
    )
  )
);

CREATE INDEX due_device_collection_checks ON public.device_collection_checks USING btree (next_check_at, lease_until);

CREATE TABLE executor_tasks (
  nonce text NOT NULL,
  owner_id text NOT NULL,
  job_id text NOT NULL,
  binding jsonb NOT NULL,
  expires_at bigint NOT NULL,
  consumed boolean NOT NULL DEFAULT false,
  CONSTRAINT executor_tasks_job_id_owner_id_fkey FOREIGN KEY (job_id, owner_id) REFERENCES jobs (id, owner_id),
  CONSTRAINT executor_tasks_pkey PRIMARY KEY (nonce)
);

CREATE TABLE tickets (
  token_hash text NOT NULL,
  owner_id text NOT NULL,
  artifact_id text NOT NULL,
  state text NOT NULL,
  expires_at bigint NOT NULL,
  CONSTRAINT tickets_artifact_id_owner_id_fkey FOREIGN KEY (artifact_id, owner_id) REFERENCES artifacts (id, owner_id),
  CONSTRAINT tickets_pkey PRIMARY KEY (token_hash)
);

CREATE TABLE user_apple_bindings (
  user_id text PRIMARY KEY REFERENCES users (id),
  connection_id text NOT NULL,
  connection_owner_id text NOT NULL,
  grant_id text UNIQUE,
  CHECK (
    (
      grant_id IS NULL
      AND user_id = connection_owner_id
    )
    OR (
      grant_id IS NOT NULL
      AND user_id <> connection_owner_id
    )
  ),
  FOREIGN KEY (connection_id, connection_owner_id) REFERENCES connections (id, owner_id),
  FOREIGN KEY (
    grant_id,
    user_id,
    connection_id,
    connection_owner_id
  ) REFERENCES apple_access_grants (
    id,
    recipient_id,
    connection_id,
    connection_owner_id
  )
);

INSERT INTO
  personal_state (id)
VALUES
  (1);

CREATE VIEW apple_connections AS
SELECT
  c.id,
  b.user_id AS owner_id,
  c.owner_id AS connection_owner_id,
  c.team_id,
  c.state,
  c.generation,
  c.provider,
  c.issuer_id,
  c.key_id,
  c.secret_ref,
  c.last_error,
  b.grant_id AS access_grant_id,
  g.generation AS access_grant_generation
FROM
  user_apple_bindings b
  JOIN connections c ON c.id = b.connection_id
  AND c.owner_id = b.connection_owner_id
  JOIN users u ON u.id = b.user_id
  JOIN users o ON o.id = c.owner_id
  LEFT JOIN apple_access_grants g ON g.id = b.grant_id
  AND g.recipient_id = b.user_id
  AND g.connection_id = c.id
  AND g.connection_owner_id = c.owner_id
WHERE
  u.deleted_at IS NULL
  AND u.blocked_at IS NULL
  AND o.deleted_at IS NULL
  AND o.blocked_at IS NULL
  AND (
    b.grant_id IS NULL
    OR (
      g.state = 'accepted'
      AND g.connection_generation = c.generation
    )
  );

CREATE VIEW signing_devices AS
SELECT
  d.*
FROM
  devices d
  JOIN apple_connections c ON c.id = d.connection_id
  AND c.owner_id = d.owner_id
WHERE
  d.connection_owner_id = c.connection_owner_id
  AND d.access_grant_id IS NOT DISTINCT FROM c.access_grant_id
  AND d.access_grant_generation IS NOT DISTINCT FROM c.access_grant_generation
  AND d.enrollment_verified_at IS NOT NULL;

CREATE VIEW signing_jobs AS
SELECT
  j.*
FROM
  jobs j
  JOIN apple_connections c ON c.id = j.connection_id
  AND c.owner_id = j.owner_id
WHERE
  j.connection_owner_id = c.connection_owner_id
  AND j.access_grant_id IS NOT DISTINCT FROM c.access_grant_id
  AND j.access_grant_generation IS NOT DISTINCT FROM c.access_grant_generation;

CREATE VIEW signing_artifacts AS
SELECT
  a.*
FROM
  artifacts a
  JOIN apple_connections c ON c.id = a.connection_id
  AND c.owner_id = a.owner_id
WHERE
  a.connection_owner_id = c.connection_owner_id
  AND a.access_grant_id IS NOT DISTINCT FROM c.access_grant_id
  AND a.access_grant_generation IS NOT DISTINCT FROM c.access_grant_generation;

CREATE UNIQUE INDEX sources_one_iapps_per_owner ON sources (owner_id)
WHERE
  kind = 'iapps';

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

-- Separate exportable client identity. Server distribution-key/bootstrap readers are unchanged.
CREATE TABLE feather_signing_identities (
  id text PRIMARY KEY,
  replacement_for text REFERENCES feather_signing_identities (id),
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
  state <> 'retired'
  AND replacement_for IS NULL;

CREATE UNIQUE INDEX feather_pending_replacement ON feather_signing_identities (connection_id, generation)
WHERE
  state <> 'retired'
  AND replacement_for IS NOT NULL;

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

CREATE TABLE client_installations (
  id text PRIMARY KEY,
  owner_id text NOT NULL,
  request_key text NOT NULL,
  job_id text NOT NULL,
  device_id text NOT NULL,
  release_sha256 text NOT NULL CHECK (release_sha256 ~ '^[a-f0-9]{64}$'),
  version text,
  receive_started_at bigint,
  created_at bigint NOT NULL,
  UNIQUE (owner_id, request_key),
  UNIQUE (job_id, owner_id),
  FOREIGN KEY (job_id, owner_id) REFERENCES jobs (id, owner_id) ON DELETE CASCADE,
  FOREIGN KEY (device_id, owner_id) REFERENCES devices (id, owner_id)
);
