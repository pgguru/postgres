/* contrib/pg_stat_statements/pg_stat_statements--1.9--1.10.sql */

-- complain if script is sourced in psql, rather than via ALTER EXTENSION
\echo Use "ALTER EXTENSION pg_stat_statements UPDATE TO '1.10'" to load this file. \quit

/* First we have to remove them from the extension */
ALTER EXTENSION pg_stat_statements DROP VIEW pg_stat_statements;
ALTER EXTENSION pg_stat_statements DROP FUNCTION pg_stat_statements(boolean);

/* Then we can drop them */
DROP VIEW pg_stat_statements;
DROP FUNCTION pg_stat_statements(boolean);

/* Now redefine */
CREATE FUNCTION pg_stat_statements(IN showtext boolean,
    OUT userid oid,
    OUT dbid oid,
    OUT toplevel bool,
    OUT queryid bigint,
    OUT query text,
    OUT plans int8,
    OUT total_plan_time float8,
    OUT min_plan_time float8,
    OUT max_plan_time float8,
    OUT mean_plan_time float8,
    OUT stddev_plan_time float8,
    OUT calls int8,
    OUT total_exec_time float8,
    OUT min_exec_time float8,
    OUT max_exec_time float8,
    OUT mean_exec_time float8,
    OUT stddev_exec_time float8,
    OUT rows int8,
    OUT shared_hit_bytes numeric,
    OUT shared_read_bytes numeric,
    OUT shared_dirtied_bytes numeric,
    OUT shared_written_bytes numeric,
    OUT local_hit_bytes numeric,
    OUT local_read_bytes numeric,
    OUT local_dirtied_bytes numeric,
    OUT local_written_bytes numeric,
    OUT temp_read_bytes numeric,
    OUT temp_written_bytes numeric,
    OUT blk_read_time float8,
    OUT blk_write_time float8,
    OUT wal_records int8,
    OUT wal_fpi int8,
    OUT wal_bytes numeric
)
RETURNS SETOF record
AS 'MODULE_PATHNAME', 'pg_stat_statements_1_10'
LANGUAGE C STRICT VOLATILE PARALLEL SAFE;

CREATE VIEW pg_stat_statements AS
  SELECT * FROM pg_stat_statements(true);

GRANT SELECT ON pg_stat_statements TO PUBLIC;
