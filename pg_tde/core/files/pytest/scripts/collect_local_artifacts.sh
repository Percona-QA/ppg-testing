#!/usr/bin/env bash
# Bundle a local pytest run's logs/reports into one tarball — the local
# equivalent of pg_tde/core/tasks/collect_artifacts.yml (what Jenkins
# packages and uploads as a build artifact).
#
# Run this AFTER a local pytest run, from the pytest/ directory:
#   cd postgresql/pytest
#   ./scripts/collect_local_artifacts.sh
#
# Picks up, if present:
#   - <RUN_DIR>/pytest_failed/           (per-failed-test server.log snapshots,
#                                          + full PGDATA if PYTEST_KEEP_FAILED_PGDATA=1)
#   - <BASETEMP>/                        (pytest --basetemp root: every test's tmp_path)
#   - <JUNIT_XML>, <HTML_REPORT>         (--junitxml / --html, if you passed them)
#
# None of these are required to exist — whatever's there gets picked up;
# whatever isn't is silently skipped, same as the Jenkins version.
#
# Env overrides (defaults match this suite's usual local invocation):
#   RUN_DIR       (default: /tmp/pgtest_pytest)     — matches --run-dir / RUN_DIR
#   BASETEMP      (default: /tmp/pg_tde_pytest_run) — matches --basetemp
#   JUNIT_XML     (default: /tmp/pg_tde_pytest_junit.xml)
#   HTML_REPORT   (default: /tmp/pg_tde_pytest_report.html)
#   OUT_DIR       (default: ./artifacts)            — where the tarball is written
set -euo pipefail

RUN_DIR="${RUN_DIR:-/tmp/pgtest_pytest}"
BASETEMP="${BASETEMP:-/tmp/pg_tde_pytest_run}"
JUNIT_XML="${JUNIT_XML:-/tmp/pg_tde_pytest_junit.xml}"
HTML_REPORT="${HTML_REPORT:-/tmp/pg_tde_pytest_report.html}"
OUT_DIR="${OUT_DIR:-./artifacts}"

STAMP="$(date +%Y%m%d-%H%M%S)"
BASENAME="pg_tde-pytest-local-${STAMP}"
STAGING="$(mktemp -d)/${BASENAME}"
mkdir -p "${STAGING}"

echo "Collecting local pytest artifacts into ${STAGING} ..."

copied_anything=false

if [ -f "${JUNIT_XML}" ]; then
    cp "${JUNIT_XML}" "${STAGING}/"
    echo "  + $(basename "${JUNIT_XML}")"
    copied_anything=true
fi

if [ -f "${HTML_REPORT}" ]; then
    cp "${HTML_REPORT}" "${STAGING}/"
    echo "  + $(basename "${HTML_REPORT}")"
    copied_anything=true
fi

if [ -d "${RUN_DIR}/pytest_failed" ]; then
    mkdir -p "${STAGING}/pytest_failed"
    cp -r "${RUN_DIR}/pytest_failed/." "${STAGING}/pytest_failed/"
    echo "  + pytest_failed/ (from ${RUN_DIR})"
    copied_anything=true
else
    echo "  - no ${RUN_DIR}/pytest_failed (no failures, or RUN_DIR doesn't match your run)"
fi

if [ -d "${BASETEMP}" ]; then
    mkdir -p "${STAGING}/basetemp"
    cp -r "${BASETEMP}/." "${STAGING}/basetemp/"
    echo "  + basetemp/ (from ${BASETEMP})"
    copied_anything=true
else
    echo "  - no ${BASETEMP} (pass --basetemp=${BASETEMP} to pytest to get this)"
fi

if [ "${copied_anything}" = false ]; then
    echo "Nothing found to collect — did the pytest run actually happen, and do" >&2
    echo "RUN_DIR/BASETEMP/JUNIT_XML/HTML_REPORT match what you passed to pytest?" >&2
    rm -rf "$(dirname "${STAGING}")"
    exit 1
fi

mkdir -p "${OUT_DIR}"
TARBALL="${OUT_DIR}/${BASENAME}.tar.gz"
tar -czf "${TARBALL}" -C "$(dirname "${STAGING}")" "${BASENAME}"
rm -rf "$(dirname "${STAGING}")"

echo ""
echo "Wrote ${TARBALL}"
