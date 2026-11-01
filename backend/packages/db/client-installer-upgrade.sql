-- Run explicitly as the schema owner, with the previous server stopped.
-- Fresh installations already use schema.sql and do not need this step.
BEGIN;

DROP TABLE IF EXISTS public.selections;

DROP TABLE IF EXISTS public.imports;

ALTER TABLE public.uploads
DROP COLUMN IF EXISTS provenance;

COMMIT;
