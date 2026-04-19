-- Enable the dblink extension so that SQL injection payloads can
-- reach out-of-band via dblink_connect(). The Postgres docker image
-- runs everything in /docker-entrypoint-initdb.d against POSTGRES_DB
-- on first boot with superuser rights, which is what this CREATE
-- EXTENSION needs.
CREATE EXTENSION IF NOT EXISTS dblink;
