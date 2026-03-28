#!/bin/bash

source validation/bin/activate
pip install --upgrade pip
pip install psycopg2-binary pytest-testinfra requests pytest pytest-order

#Run test without shared_preload_libraries  (default)
pytest test_docker.py -vv -s -rpfs -m "not needs_preload"

#Run test with shared_preload_libraries (timescaledb and pg_stat_monitor)
pytest test_docker.py -vv -s -rpfs -m "needs_preload"

#Run test for Patroni HA
pytest test_patroni_ha.py -vv -s -rpfs

#Run test for pgbackrest
pytest test_pgbackrest.py -vv -s -rpfs
