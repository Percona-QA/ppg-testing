#!/bin/bash
# =============================================================================
# run.sh — Full upgrade test orchestrator
#
# Phases
# ──────
#   Phase 1  Test OLD_VERSION image with the standard test suite.
#   Phase 2  Run pg_upgrade mediator, then verify data integrity with
#            test_upgrade.py (SKIP_UPGRADE=true reuses the upgraded data).
#   Phase 3  Test NEW_VERSION image with the standard test suite.
#
# Required environment variables
# ────────────────────────────────
#   OLD_VERSION        Full source version    e.g. "17.10"
#   NEW_VERSION        Full target version    e.g. "18.4"
#   DOCKER_REPOSITORY  Image registry prefix  e.g. "perconalab"
#   UPGRADE_TAG        Mediator image tag     e.g. "18-17-16"
#
# Optional environment variables
# ────────────────────────────────
#   OLD_TAG           Tag for old custom image     (default: OLD_VERSION)
#   NEW_TAG           Tag for new custom image     (default: NEW_VERSION)
#   WITH_POSTGIS      Enable PostGIS tests         (default: false)
#
# Mediator tag
# ────────────
#   The mediator tag encodes the full supported version chain.
#   "18-17-16" supports both PG 16 → 17 and PG 17 → 18 upgrades.
#   The older "v2" tag is broken for pre-PG18 targets (uses --no-data-checksums
#   which was introduced in PG 18) and should not be used.
#
# Volume strategy
# ───────────────
#   Named Docker volumes are used instead of host bind mounts.  This avoids
#   chmod/chown permission failures that occur in CI environments running
#   rootless Docker or Docker-in-Docker, where the container's root user cannot
#   modify bind-mounted directories owned by a different host UID.
#
# Usage examples
# ──────────────
#   # PG 17 → PG 18
#   OLD_VERSION=17.10 NEW_VERSION=18.4 DOCKER_REPOSITORY=perconalab \
#       OLD_TAG=17.10 NEW_TAG=18.4 UPGRADE_TAG=18-17-16 \
#       WITH_POSTGIS=true ./run.sh
#
#   # PG 16 → PG 17
#   OLD_VERSION=16.14 NEW_VERSION=17.10 DOCKER_REPOSITORY=perconalab \
#       OLD_TAG=16.14 NEW_TAG=17.10 UPGRADE_TAG=18-17-16 \
#       WITH_POSTGIS=true ./run.sh
# =============================================================================
set -uo pipefail

# ── Resolve configuration ────────────────────────────────────────────────────

OLD_VERSION="${OLD_VERSION:-17.10}"
NEW_VERSION="${NEW_VERSION:-18.4}"
OLD_MAJOR="${OLD_VERSION%%.*}"
NEW_MAJOR="${NEW_VERSION%%.*}"
DOCKER_REPOSITORY="${DOCKER_REPOSITORY:-perconalab}"
OLD_TAG="${OLD_TAG:-$OLD_VERSION}"
NEW_TAG="${NEW_TAG:-$NEW_VERSION}"
: "${UPGRADE_TAG:?UPGRADE_TAG is required. e.g. UPGRADE_TAG=18-17-16}"
WITH_POSTGIS="${WITH_POSTGIS:-false}"

# Warn if the broken legacy "v2" mediator tag is used — it passes
# --no-data-checksums to initdb which was only introduced in PG 18 and
# causes initdb to fail for any upgrade path.
if [ "${UPGRADE_TAG}" = "v2" ]; then
    echo ""
    echo "  WARNING: mediator tag 'v2' is broken for all upgrade paths."
    echo "  It passes --no-data-checksums (PG 18+ only) causing initdb to fail."
    echo "  Use UPGRADE_TAG=18-17-16 instead."
    echo ""
fi

OLD_IMAGE="$DOCKER_REPOSITORY/percona-distribution-postgresql-custom:$OLD_TAG"
NEW_IMAGE="$DOCKER_REPOSITORY/percona-distribution-postgresql-custom:$NEW_TAG"
UPGRADE_IMAGE="$DOCKER_REPOSITORY/percona-distribution-postgresql-upgrade-custom:$UPGRADE_TAG"

# Named Docker volumes — avoids all bind-mount permission issues in CI.
# Each run gets a unique suffix so parallel jobs do not collide.
OLD_VOL="ppg_upgrade_old_${OLD_MAJOR}_${NEW_MAJOR}"
NEW_VOL="ppg_upgrade_new_${OLD_MAJOR}_${NEW_MAJOR}"

PHASE1_RC=0
PHASE2_RC=0
PHASE3_RC=0

# ── Python environment ───────────────────────────────────────────────────────

source validation/bin/activate
pip install --upgrade pip --quiet
pip install psycopg2-binary pytest-testinfra requests pytest pytest-order --quiet

# ── Helpers ───────────────────────────────────────────────────────────────────

_print_header() {
    echo ""
    echo "================================================================"
    echo "  $*"
    echo "================================================================"
}

_wait_for_pg() {
    local container="$1" major="$2"
    local bin_dir="/usr/pgsql-${major}/bin"
    echo "  Waiting for PostgreSQL in $container ..."
    for _i in $(seq 1 30); do
        docker exec "$container" "${bin_dir}/pg_isready" -U postgres \
            > /dev/null 2>&1 && return 0
        sleep 2
    done
    echo "  ERROR: PostgreSQL in $container not ready after 60s"
    return 1
}

# ── Named Docker volumes ──────────────────────────────────────────────────────
# Named volumes are fully managed by Docker: no host-path ownership issues,
# no chmod failures in rootless or DinD CI environments.

_print_header "Configuration"
echo "  OLD_VERSION        : $OLD_VERSION"
echo "  NEW_VERSION        : $NEW_VERSION"
echo "  OLD_MAJOR          : $OLD_MAJOR"
echo "  NEW_MAJOR          : $NEW_MAJOR"
echo "  DOCKER_REPOSITORY  : $DOCKER_REPOSITORY"
echo "  OLD_TAG            : $OLD_TAG"
echo "  NEW_TAG            : $NEW_TAG"
echo "  UPGRADE_TAG        : $UPGRADE_TAG"
echo "  WITH_POSTGIS       : $WITH_POSTGIS"
echo "  OLD_IMAGE          : $OLD_IMAGE"
echo "  NEW_IMAGE          : $NEW_IMAGE"
echo "  UPGRADE_IMAGE      : $UPGRADE_IMAGE"
echo "  OLD_VOL            : $OLD_VOL"
echo "  NEW_VOL            : $NEW_VOL"

_print_header "Preparing Docker volumes"

# Remove any leftover volumes from a previous run, then create fresh ones.
docker volume rm "$OLD_VOL" "$NEW_VOL" > /dev/null 2>&1 || true
docker volume create "$OLD_VOL" > /dev/null
docker volume create "$NEW_VOL" > /dev/null
echo "  Created Docker volumes: $OLD_VOL  $NEW_VOL"

# ═════════════════════════════════════════════════════════════════════════════
# Phase 1 — Test OLD version image
# ═════════════════════════════════════════════════════════════════════════════

_print_header "Phase 1: Testing PG $OLD_VERSION (pre-upgrade)"

VERSION=$OLD_VERSION \
TAG=$OLD_TAG \
DOCKER_REPOSITORY=$DOCKER_REPOSITORY \
WITH_POSTGIS=$WITH_POSTGIS \
UPGRADE_DATA_DIR="$OLD_VOL" \
pytest \
    test_labels_licences.py \
    test_docker.py \
    test_patroni_ha.py \
    test_pgbackrest.py \
    -vv -s -rpfs || PHASE1_RC=$?

echo ""
echo "  Phase 1 result: $( [ $PHASE1_RC -eq 0 ] && echo 'PASS' || echo "FAIL (rc=$PHASE1_RC)" )"

# ═════════════════════════════════════════════════════════════════════════════
# Phase 2 — Run pg_upgrade, then verify upgraded data
# ═════════════════════════════════════════════════════════════════════════════

_print_header "Phase 2: Upgrading PG $OLD_VERSION → PG $NEW_VERSION"

# OLD_VOL was populated by test_docker.py's session-scoped host fixture during
# Phase 1.  We must insert the sentinel row now — test_upgrade.py will verify
# it survived the upgrade.  (SKIP_UPGRADE=true skips the fixture's own sentinel
# creation, so run.sh is responsible for it here.)

SENTINEL_CONTAINER="ppg_sentinel_${OLD_MAJOR}_${NEW_MAJOR}"
SENTINEL_TABLE="upgrade_sentinel"
SENTINEL_VALUE="upgraded_from_pg${OLD_MAJOR}_to_pg${NEW_MAJOR}"

echo "  Inserting sentinel row into old cluster ..."
docker rm -f "$SENTINEL_CONTAINER" > /dev/null 2>&1 || true
docker run -d \
    --name "$SENTINEL_CONTAINER" \
    -e POSTGRES_PASSWORD=password \
    --shm-size=2g \
    -v "$OLD_VOL:/data/db" \
    "$OLD_IMAGE"

_wait_for_pg "$SENTINEL_CONTAINER" "$OLD_MAJOR"

docker exec "$SENTINEL_CONTAINER" \
    /usr/pgsql-${OLD_MAJOR}/bin/psql -U postgres -c \
    "CREATE TABLE IF NOT EXISTS ${SENTINEL_TABLE} (val TEXT);
     INSERT INTO ${SENTINEL_TABLE} VALUES ('${SENTINEL_VALUE}');"

echo "  Sentinel inserted: ${SENTINEL_TABLE}.val = '${SENTINEL_VALUE}'"
docker stop "$SENTINEL_CONTAINER" > /dev/null
docker rm   "$SENTINEL_CONTAINER" > /dev/null

# Pre-initialise the new cluster volume before running the mediator.
# This is required for two reasons:
#
# 1. Volume root ownership: Docker creates named volume roots as root:root 755.
#    The mediator's initdb runs after dropping privileges to the postgres user
#    and cannot chown the volume root directory.  pg_upgrade then fails to
#    create pg_upgrade_output.d ("Permission denied") because it runs as the
#    postgres user in a root-owned directory.  Starting the new-version image
#    here causes its entrypoint (which runs as root before dropping privileges)
#    to chown/chmod the volume root to the postgres user, giving pg_upgrade
#    the correct ownership to proceed.
#
# 2. Mediator --no-data-checksums flag (PG < 18 only): the mediator passes
#    this initdb flag which was introduced in PG 18.  For older targets initdb
#    fails immediately before writing anything.  By pre-initialising here the
#    cluster already exists when the mediator's initdb fails, and pg_upgrade
#    finds a valid cluster to upgrade into.
echo "  Pre-initialising new cluster ..."
PREINIT_CONTAINER="ppg_preinit_${OLD_MAJOR}_${NEW_MAJOR}"
docker rm -f "$PREINIT_CONTAINER" > /dev/null 2>&1 || true

# PG 18+ enables data checksums by default; the old cluster was initialized
# without checksums, so pg_upgrade requires the new cluster to also have none.
# Pass --no-data-checksums only for PG 18+ — earlier versions do not support
# the flag (it was introduced in PG 18) and their default is already no checksums.
PREINIT_INITDB_ARGS=()
if [ "${NEW_MAJOR}" -ge 18 ]; then
    PREINIT_INITDB_ARGS=(-e POSTGRES_INITDB_ARGS="--no-data-checksums")
fi

docker run -d \
    --name "$PREINIT_CONTAINER" \
    -e POSTGRES_PASSWORD=password \
    "${PREINIT_INITDB_ARGS[@]}" \
    --shm-size=2g \
    -v "$NEW_VOL:/data/db" \
    "$NEW_IMAGE"
_wait_for_pg "$PREINIT_CONTAINER" "$NEW_MAJOR"
docker stop "$PREINIT_CONTAINER" > /dev/null
docker rm   "$PREINIT_CONTAINER" > /dev/null
echo "  New cluster pre-initialised in volume $NEW_VOL"

# Run the pg_upgrade mediator.
# The named volumes are mounted directly at the paths the mediator expects:
#   /pgolddata/postgres  — old cluster root
#   /pgnewdata/postgres  — new cluster root (mediator writes here)
echo "  Running pg_upgrade mediator ..."
docker run --rm \
    --name "ppg_upgrade_mediator_${OLD_MAJOR}_${NEW_MAJOR}" \
    -e OLD_VERSION="$OLD_MAJOR" \
    -e NEW_VERSION="$NEW_MAJOR" \
    -e OLD_DATABASE_NAME=postgres \
    -e NEW_DATABASE_NAME=postgres \
    -v "$OLD_VOL:/pgolddata/postgres" \
    -v "$NEW_VOL:/pgnewdata/postgres" \
    "$UPGRADE_IMAGE" || PHASE2_RC=$?

echo "  Upgrade mediator exit code: $PHASE2_RC"

# Print the loadable_libraries report when the mediator fails.
if [ $PHASE2_RC -ne 0 ]; then
    echo ""
    echo "  ── loadable_libraries.txt ──────────────────────────────────"
    docker run --rm \
        -v "$NEW_VOL:/pgnewdata/postgres" \
        "$NEW_IMAGE" \
        sh -c "cat /pgnewdata/postgres/pg_upgrade_output.d/loadable_libraries.txt 2>/dev/null || echo '  (file not found)'"
    echo "  ────────────────────────────────────────────────────────────"
fi

# Run upgrade-specific data integrity tests if the upgrade succeeded.
# SKIP_UPGRADE=true tells test_upgrade.py to reuse the volumes that were
# just populated above instead of repeating the upgrade itself.
if [ $PHASE2_RC -eq 0 ]; then
    echo ""
    echo "  Running upgrade data integrity tests (test_upgrade.py) ..."
    OLD_VERSION=$OLD_VERSION \
    NEW_VERSION=$NEW_VERSION \
    DOCKER_REPOSITORY=$DOCKER_REPOSITORY \
    OLD_TAG=$OLD_TAG \
    NEW_TAG=$NEW_TAG \
    UPGRADE_TAG=$UPGRADE_TAG \
    UPGRADE_NEW_VOL=$NEW_VOL \
    SKIP_UPGRADE=true \
    pytest test_upgrade.py -vv -s -rpfs || PHASE2_RC=$?
else
    echo "  Skipping data integrity tests — upgrade mediator failed."
fi

echo ""
echo "  Phase 2 result: $( [ $PHASE2_RC -eq 0 ] && echo 'PASS' || echo "FAIL (rc=$PHASE2_RC)" )"

# ═════════════════════════════════════════════════════════════════════════════
# Phase 3 — Test NEW version image
# ═════════════════════════════════════════════════════════════════════════════

_print_header "Phase 3: Testing PG $NEW_VERSION (post-upgrade)"

VERSION=$NEW_VERSION \
TAG=$NEW_TAG \
DOCKER_REPOSITORY=$DOCKER_REPOSITORY \
WITH_POSTGIS=$WITH_POSTGIS \
UPGRADE_DATA_DIR="$NEW_VOL" \
pytest \
    test_labels_licences.py \
    test_docker.py \
    test_patroni_ha.py \
    test_pgbackrest.py \
    -vv -s -rpfs || PHASE3_RC=$?

echo ""
echo "  Phase 3 result: $( [ $PHASE3_RC -eq 0 ] && echo 'PASS' || echo "FAIL (rc=$PHASE3_RC)" )"

# ═════════════════════════════════════════════════════════════════════════════
# Cleanup
# ═════════════════════════════════════════════════════════════════════════════

_print_header "Cleanup"
docker volume rm "$OLD_VOL" "$NEW_VOL" > /dev/null 2>&1 || true
echo "  Removed Docker volumes: $OLD_VOL  $NEW_VOL"

# ═════════════════════════════════════════════════════════════════════════════
# Summary
# ═════════════════════════════════════════════════════════════════════════════

_print_header "Upgrade Test Summary: PG $OLD_VERSION → PG $NEW_VERSION"
echo "  Phase 1  Pre-upgrade (PG $OLD_VERSION):                 $( [ $PHASE1_RC -eq 0 ] && echo 'PASS' || echo "FAIL (rc=$PHASE1_RC)" )"
echo "  Phase 2  PG Upgrade (PG $OLD_MAJOR → PG $NEW_MAJOR):    $( [ $PHASE2_RC -eq 0 ] && echo 'PASS' || echo "FAIL (rc=$PHASE2_RC)" )"
echo "  Phase 3  Post-upgrade (PG $NEW_VERSION):                $( [ $PHASE3_RC -eq 0 ] && echo 'PASS' || echo "FAIL (rc=$PHASE3_RC)" )"
echo ""

[ $PHASE1_RC -eq 0 ] && [ $PHASE2_RC -eq 0 ] && [ $PHASE3_RC -eq 0 ] || exit 1
echo "All phases passed."
