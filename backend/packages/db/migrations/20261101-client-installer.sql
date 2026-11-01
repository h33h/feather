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
