-- Retain one usable identity while preparing one durable renewal candidate.
ALTER TABLE feather_signing_identities
ADD COLUMN replacement_for text REFERENCES feather_signing_identities (id);

DROP INDEX feather_current_identity;

CREATE UNIQUE INDEX feather_current_identity ON feather_signing_identities (connection_id, generation)
WHERE
  state <> 'retired'
  AND replacement_for IS NULL;

CREATE UNIQUE INDEX feather_pending_replacement ON feather_signing_identities (connection_id, generation)
WHERE
  state <> 'retired'
  AND replacement_for IS NOT NULL;
