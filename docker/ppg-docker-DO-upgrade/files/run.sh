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
#   OLD_VERSION        Full source version    e.g. "17.9"
#   NEW_VERSION        Full target version    e.g. "18.3"
#   DOCKER_REPOSITORY  Image registry prefix  e.g. "perconalab"
#   UPGRADE_TAG        Mediator image tag     e.g. "18.3-17.9-16.13-1"
#
# Optional environment variables
# ────────────────────────────────
#   OLD_TAG           Tag for old custom image     (default: OLD_VERSION)
#   NEW_TAG           Tag for new custom image     (default: NEW_VERSION)
#   MILESTONE         Milestone level for tests    (default: 0)
#   WITH_POSTGIS      Enable PostGIS tests         (default: false)
#
# Mediator tag
# ────────────
#   The mediator tag encodes the full supported version chain.
#   "18.3-17.9-16.13-1" supports both PG 16 → 17 and PG 17 → 18 upgrades.
#   The older "v2" tag is broken for pre-PG18 targets (uses --no-data-checksums
#   which was introduced in PG 18) and should not be used.
#
# Usage examples
# ──────────────
#   # PG 17 → PG 18
#   OLD_VERSION=17.9 NEW_VERSION=18.3 DOCKER_REPOSITORY=perconalab \
#       OLD_TAG=17.9-v2 NEW_TAG=18.3-v2 UPGRADE_TAG=18.3-17.9-16.13-1 \
#       MILESTONE=2 WITH_POSTGIS=true ./run.sh
#
#   # PG 16 → PG 17
#   OLD_VERSION=16.13 NEW_VERSION=17.9 DOCKER_REPOSITORY=perconalab \
#       OLD_TAG=16.13-v2 NEW_TAG=17.9-v2 UPGRADE_TAG=18.3-17.9-16.13-1 \
#       MILESTONE=2 WITH_POSTGIS=true ./run.sh
# =============================================================================
set -uo pipefail

# ── Resolve configuration ────────────────────────────────────────────────────

OLD_VERSION="${OLD_VERSION:-17.9}"
NEW_VERSION="${NEW_VERSION:-18.3}"
OLD_MAJOR="${OLD_VERSION%%.*}"
NEW_MAJOR="${NEW_VERSION%%.*}"
DOCKER_REPOSITORY="${DOCKER_REPOSITORY:-perconalab}"
OLD_TAG="${OLD_TAG:-$OLD_VERSION}"
NEW_TAG="${NEW_TAG:-$NEW_VERSION}"
: "${UPGRADE_TAG:?UPGRADE_TAG is required. e.g. UPGRADE_TAG=18.3-17.9-16.13-1}"
UPGRADE_BASE_DIR="/tmp/pgupgrade"
MILESTONE="${MILESTONE:-0}"
WITH_POSTGIS="${WITH_POSTGIS:-false}"

# Warn if the broken legacy "v2" mediator tag is used — it passes
# --no-data-checksums to initdb which was only introduced in PG 18 and
# causes initdb to fail for any upgrade path.
if [ "${UPGRADE_TAG}" = "v2" ]; then
    echo ""
    echo "  WARNING: mediator tag 'v2' is broken for all upgrade paths."
    echo "  It passes --no-data-checksums (PG 18+ only) causing initdb to fail."
    echo "  Use UPGRADE_TAG=18.3-17.9-16.13-1 instead."
    echo ""
fi

OLD_IMAGE="$DOCKER_REPOSITORY/percona-distribution-postgresql-custom:$OLD_TAG"
NEW_IMAGE="$DOCKER_REPOSITORY/percona-distribution-postgresql-custom:$NEW_TAG"
UPGRADE_IMAGE="$DOCKER_REPOSITORY/percona-distribution-postgresql-upgrade-custom:$UPGRADE_TAG"

OLD_DATA="$UPGRADE_BASE_DIR/pg${OLD_MAJOR}olddata"
NEW_DATA="$UPGRADE_BASE_DIR/pg${NEW_MAJOR}newdata"

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

# ── Volume directories ────────────────────────────────────────────────────────
# Create fresh volume directories before Phase 1.  test_docker.py's host
# fixture will start the old container with $OLD_DATA/postgres mounted and
# PostgreSQL will initialise a new cluster there on first boot.  That same
# data is then upgraded in Phase 2 and tested again in Phase 3.

_print_header "Configuration"
echo "  OLD_VERSION        : $OLD_VERSION"
echo "  NEW_VERSION        : $NEW_VERSION"
echo "  OLD_MAJOR          : $OLD_MAJOR"
echo "  NEW_MAJOR          : $NEW_MAJOR"
echo "  DOCKER_REPOSITORY  : $DOCKER_REPOSITORY"
echo "  OLD_TAG            : $OLD_TAG"
echo "  NEW_TAG            : $NEW_TAG"
echo "  UPGRADE_TAG        : $UPGRADE_TAG"
echo "  UPGRADE_BASE_DIR   : $UPGRADE_BASE_DIR"
echo "  MILESTONE          : $MILESTONE"
echo "  WITH_POSTGIS       : $WITH_POSTGIS"
echo "  OLD_IMAGE          : $OLD_IMAGE"
echo "  NEW_IMAGE          : $NEW_IMAGE"
echo "  UPGRADE_IMAGE      : $UPGRADE_IMAGE"
echo "  OLD_DATA           : $OLD_DATA"
echo "  NEW_DATA           : $NEW_DATA"

_print_header "Preparing volume directories"

rm -rf "$OLD_DATA" "$NEW_DATA"
mkdir -p "$OLD_DATA/postgres" "$NEW_DATA/postgres"
# The container's entrypoint runs chown/chmod on the data directory as the
# postgres user.  If the directory was created by root (common in CI), the
# container cannot change its permissions and fails to start.  Set 777 here
# so the container can take ownership on first boot.
chmod -R 777 "$OLD_DATA" "$NEW_DATA"
echo "  Old data dir : $OLD_DATA/postgres"
echo "  New data dir : $NEW_DATA/postgres"

# ═════════════════════════════════════════════════════════════════════════════
# Phase 1 — Test OLD version image (seeds $OLD_DATA/postgres as a side-effect)
# ═════════════════════════════════════════════════════════════════════════════

_print_header "Phase 1: Testing PG $OLD_VERSION (pre-upgrade)"

VERSION=$OLD_VERSION \
TAG=$OLD_TAG \
DOCKER_REPOSITORY=$DOCKER_REPOSITORY \
MILESTONE=$MILESTONE \
WITH_POSTGIS=$WITH_POSTGIS \
UPGRADE_DATA_DIR="$OLD_DATA/postgres" \
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

# $OLD_DATA/postgres was populated by test_docker.py's session-scoped host
# fixture during Phase 1 (the container was started with that volume and
# PostgreSQL initialised the cluster there on first boot).  No seed step is
# needed here — but we must insert the sentinel row that test_upgrade.py will
# verify after the upgrade (SKIP_UPGRADE=true mode skips the fixture's own
# sentinel creation, so run.sh is responsible for it).

SENTINEL_CONTAINER="ppg_sentinel_${OLD_MAJOR}_${NEW_MAJOR}"
SENTINEL_TABLE="upgrade_sentinel"
SENTINEL_VALUE="upgraded_from_pg${OLD_MAJOR}_to_pg${NEW_MAJOR}"

echo "  Inserting sentinel row into old cluster ..."
docker rm -f "$SENTINEL_CONTAINER" > /dev/null 2>&1 || true
docker run -d \
    --name "$SENTINEL_CONTAINER" \
    -e POSTGRES_PASSWORD=password \
    --shm-size=2g \
    -v "$OLD_DATA/postgres:/data/db" \
    "$OLD_IMAGE"

_wait_for_pg "$SENTINEL_CONTAINER" "$OLD_MAJOR"

docker exec "$SENTINEL_CONTAINER" \
    /usr/pgsql-${OLD_MAJOR}/bin/psql -U postgres -c \
    "CREATE TABLE IF NOT EXISTS ${SENTINEL_TABLE} (val TEXT);
     INSERT INTO ${SENTINEL_TABLE} VALUES ('${SENTINEL_VALUE}');"

echo "  Sentinel inserted: ${SENTINEL_TABLE}.val = '${SENTINEL_VALUE}'"
docker stop "$SENTINEL_CONTAINER" > /dev/null
docker rm   "$SENTINEL_CONTAINER" > /dev/null

# Pre-initialize the new cluster when the mediator targets PG < 18.
# The mediator uses --no-data-checksums with initdb, a flag introduced in
# PG 18.  For older targets initdb exits immediately on the unrecognised flag
# before touching the directory.  By pre-initialising the new data directory
# here the mediator's failed initdb leaves it intact, and pg_upgrade then
# finds a valid cluster to upgrade into.
if [ "${NEW_MAJOR}" -lt 18 ]; then
    echo "  Pre-initialising new cluster (PG${NEW_MAJOR} mediator workaround) ..."
    PREINIT_CONTAINER="ppg_preinit_${OLD_MAJOR}_${NEW_MAJOR}"
    docker rm -f "$PREINIT_CONTAINER" > /dev/null 2>&1 || true
    docker run -d \
        --name "$PREINIT_CONTAINER" \
        -e POSTGRES_PASSWORD=password \
        --shm-size=2g \
        -v "$NEW_DATA/postgres:/data/db" \
        "$NEW_IMAGE"
    _wait_for_pg "$PREINIT_CONTAINER" "$NEW_MAJOR"
    docker stop "$PREINIT_CONTAINER" > /dev/null
    docker rm   "$PREINIT_CONTAINER" > /dev/null
    echo "  New cluster pre-initialised at $NEW_DATA/postgres"
fi

# Run the pg_upgrade mediator
echo "  Running pg_upgrade mediator ..."
docker run --rm \
    --name "ppg_upgrade_mediator_${OLD_MAJOR}_${NEW_MAJOR}" \
    -e OLD_VERSION="$OLD_MAJOR" \
    -e NEW_VERSION="$NEW_MAJOR" \
    -e OLD_DATABASE_NAME=postgres \
    -e NEW_DATABASE_NAME=postgres \
    -v "$OLD_DATA:/pgolddata" \
    -v "$NEW_DATA:/pgnewdata" \
    "$UPGRADE_IMAGE" || PHASE2_RC=$?

echo "  Upgrade mediator exit code: $PHASE2_RC"

# Print the loadable_libraries report whenever the mediator fails — it lists
# exactly which .so files pg_upgrade could not find in the new installation.
if [ $PHASE2_RC -ne 0 ]; then
    LIBS_FILE=$(find "$NEW_DATA/postgres/pg_upgrade_output.d" \
        -name "loadable_libraries.txt" 2>/dev/null | head -1)
    if [ -n "$LIBS_FILE" ]; then
        echo ""
        echo "  ── loadable_libraries.txt ──────────────────────────────────"
        cat "$LIBS_FILE"
        echo "  ────────────────────────────────────────────────────────────"
    fi
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
    UPGRADE_BASE_DIR=$UPGRADE_BASE_DIR \
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
MILESTONE=$MILESTONE \
WITH_POSTGIS=$WITH_POSTGIS \
UPGRADE_DATA_DIR="$NEW_DATA/postgres" \
pytest \
    test_labels_licences.py \
    test_docker.py \
    test_patroni_ha.py \
    test_pgbackrest.py \
    -vv -s -rpfs || PHASE3_RC=$?

echo ""
echo "  Phase 3 result: $( [ $PHASE3_RC -eq 0 ] && echo 'PASS' || echo "FAIL (rc=$PHASE3_RC)" )"

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
