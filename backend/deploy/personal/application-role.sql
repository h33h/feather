-- Reviewable provisioning template. Never run unchanged; password is a placeholder.
-- Connect as the dedicated isign_admin, not another project's database administrator.
CREATE ROLE isign LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION PASSWORD 'INJECT_APPLICATION_SECRET_WITH_APPROVED_OPERATOR_TOOL';

ALTER DATABASE isign OWNER TO isign;

-- Connect to the dedicated isign database as isign and initialize the empty schema and admin using personal:admin init ADMIN_LOGIN.
-- No port5432 on the host, no grants to unrelated databases or schemas.
