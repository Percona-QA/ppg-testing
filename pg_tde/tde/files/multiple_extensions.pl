#!/usr/bin/perl

use strict;
use warnings;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

my ($cmdret, $stdout, $stderr);

my $keydir = PostgreSQL::Test::Utils::tempdir;

my $node = PostgreSQL::Test::Cluster->new('main');
$node->init;
$node->append_conf('postgresql.conf',
	"shared_preload_libraries = 'pg_tde, pg_stat_monitor, pgaudit, set_user, pg_repack'"
);
$node->append_conf('postgresql.conf', "pg_stat_monitor.pgsm_bucket_time = 360000");
$node->append_conf('postgresql.conf', "pg_stat_monitor.pgsm_normalized_query = 'yes'");
$node->start;

# Create extensions
($cmdret, $stdout, $stderr) = $node->psql('postgres',
	'CREATE EXTENSION IF NOT EXISTS pg_stat_monitor;');
is($cmdret, 0, 'CREATE pg_stat_monitor EXTENSION');

($cmdret, $stdout, $stderr) = $node->psql('postgres',
	'SELECT pg_stat_monitor_reset();');
is($cmdret, 0, 'Reset pg_stat_monitor');

($cmdret, $stdout, $stderr) = $node->psql('postgres',
	'CREATE EXTENSION pg_tde;');
is($cmdret, 0, 'CREATE pg_tde EXTENSION');

($cmdret, $stdout, $stderr) = $node->psql('postgres',
	'CREATE EXTENSION IF NOT EXISTS pgaudit;');
is($cmdret, 0, 'CREATE pgaudit EXTENSION');

($cmdret, $stdout, $stderr) = $node->psql('postgres',
	'CREATE EXTENSION IF NOT EXISTS set_user;');
is($cmdret, 0, 'CREATE set_user EXTENSION');

($cmdret, $stdout, $stderr) = $node->psql('postgres',
	'CREATE EXTENSION IF NOT EXISTS pg_repack;');
is($cmdret, 0, 'CREATE pg_repack EXTENSION');

($cmdret, $stdout, $stderr) = $node->psql('postgres',
	"SET pgaudit.log = 'none'; CREATE EXTENSION IF NOT EXISTS postgis; SET pgaudit.log = 'all';");
is($cmdret, 0, 'CREATE postgis EXTENSION');

($cmdret, $stdout, $stderr) = $node->psql('postgres',
	'CREATE EXTENSION IF NOT EXISTS postgis_raster;');
is($cmdret, 0, 'CREATE postgis_raster EXTENSION');

($cmdret, $stdout, $stderr) = $node->psql('postgres',
	'CREATE EXTENSION IF NOT EXISTS postgis_sfcgal;');
is($cmdret, 0, 'CREATE postgis_sfcgal EXTENSION');

($cmdret, $stdout, $stderr) = $node->psql('postgres',
	'CREATE EXTENSION IF NOT EXISTS fuzzystrmatch;');
is($cmdret, 0, 'CREATE fuzzystrmatch EXTENSION');

($cmdret, $stdout, $stderr) = $node->psql('postgres',
	'CREATE EXTENSION IF NOT EXISTS address_standardizer;');
is($cmdret, 0, 'CREATE address_standardizer EXTENSION');

($cmdret, $stdout, $stderr) = $node->psql('postgres',
	'CREATE EXTENSION IF NOT EXISTS address_standardizer_data_us;');
is($cmdret, 0, 'CREATE address_standardizer_data_us EXTENSION');

($cmdret, $stdout, $stderr) = $node->psql('postgres',
	'CREATE EXTENSION IF NOT EXISTS postgis_tiger_geocoder;');
is($cmdret, 0, 'CREATE postgis_tiger_geocoder EXTENSION');

# Set up pg_tde key provider and principal key
$node->safe_psql('postgres', qq(
	SELECT pg_tde_add_database_key_provider_file('reg_file-vault', '$keydir/multiple_ext.keys');
	SELECT pg_tde_create_key_using_database_key_provider('test-db-key', 'reg_file-vault');
	SELECT pg_tde_set_key_using_database_key_provider('test-db-key', 'reg_file-vault');
));

# Create encrypted table and insert data
$node->safe_psql('postgres',
	'CREATE TABLE test_enc1 (id SERIAL, k INTEGER, PRIMARY KEY (id)) USING tde_heap;');

$node->safe_psql('postgres',
	'INSERT INTO test_enc1 (k) VALUES (5), (6);');

$stdout = $node->safe_psql('postgres',
	'SELECT * FROM test_enc1 ORDER BY id;');
is($stdout, "1|5\n2|6", 'encrypted table data readable before restart');

# Restart and verify data survives
$node->restart;

$stdout = $node->safe_psql('postgres',
	'SELECT * FROM test_enc1 ORDER BY id;');
is($stdout, "1|5\n2|6", 'encrypted table data readable after restart');

$node->safe_psql('postgres', 'DROP TABLE test_enc1;');

# Create example database and run pgbench
($cmdret, $stdout, $stderr) = $node->psql('postgres',
	'CREATE DATABASE example;');
is($cmdret, 0, 'CREATE DATABASE example');

my $port = $node->port;

my $pgbench_init = system("pgbench -i -s 20 -p $port example");
is($pgbench_init, 0, 'pgbench init on example database');

my $pgbench_run = system("pgbench -c 10 -j 2 -t 5000 -p $port example");
is($pgbench_run, 0, 'pgbench workload on example database');

# Verify pg_stat_monitor captured queries
($cmdret, $stdout, $stderr) = $node->psql('postgres',
	'SELECT COUNT(*) FROM pg_stat_monitor;');
is($cmdret, 0, 'pg_stat_monitor has query stats');

# Cleanup
$node->safe_psql('postgres', 'DROP EXTENSION pg_tde;');
$node->safe_psql('postgres', 'DROP EXTENSION pg_stat_monitor;');

$node->stop;

done_testing();
