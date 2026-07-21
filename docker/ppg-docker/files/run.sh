#!/bin/bash
# =============================================================================
# run.sh — Docker image test runner
#
# Required environment variables (normally injected by the ppg-docker
# Ansible role's playbook.yml — set them manually only when running this
# script standalone)
# ────────────────────────────────────────────────────────────────────────────
#   VERSION            Full PG version              e.g. "18.4"
#   DOCKER_REPOSITORY   Image registry prefix        e.g. "perconalab"
#   TAG                 Image tag                    e.g. "18-ubi10"
#   WITH_POSTGIS        Enable PostGIS tests         (default: false)
#
#   Tag examples:
#     TAG=18-ubi8    (RHEL/UBI 8)
#     TAG=18         (legacy UBI 9 default)
#     TAG=18-ubi10   (RHEL/UBI 10)
# =============================================================================
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