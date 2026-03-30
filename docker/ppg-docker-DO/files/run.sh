#!/bin/bash
source validation/bin/activate
pip install psycopg2-binary
pip install pytest-testinfra requests pytest-order

pytest test_labels_licences.py \
       test_docker.py \
       test_patroni_ha.py \
       test_pgbackrest.py \
       -vv -s -rpfs

# pytest test_labels_licences.py -vv -s -rpfs
# pytest test_docker.py -vv -s -rpfs -m "not needs_preload"
# pytest test_docker.py -vv -s -rpfs -m "needs_preload"
# pytest test_patroni_ha.py -vv -s -rpfs
# pytest test_pgbackrest.py -vv -s -rpfs