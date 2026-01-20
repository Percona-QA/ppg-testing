#!/bin/bash
set -e
# echo "--- 🚀 Running Tests ---"

docker-compose down -v
docker-compose up -d

echo "--- ⏳ Waiting for PostgreSQL to be healthy ---"
PG_CONTAINER_NAME="${PG_CONTAINER_NAME:-pg_primary}"
until [ "$(docker inspect -f {{.State.Health.Status}} "${PG_CONTAINER_NAME}")" == "healthy" ]; do
    sleep 2
done

echo "--- 🧪 Running Pytest Suite ---"
PYTEST_ARGS="-q -s -o console_output_style=progress --disable-warnings"
if [ -n "${PGBACKREST_PYTEST_SELECTOR}" ]; then
  if [[ "${PGBACKREST_PYTEST_SELECTOR}" == *"::"* ]]; then
    python3 -m pytest ${PYTEST_ARGS} test_docker.py::${PGBACKREST_PYTEST_SELECTOR}
  else
    python3 -m pytest ${PYTEST_ARGS} test_docker.py -k "${PGBACKREST_PYTEST_SELECTOR}"
  fi
else
  python3 -m pytest ${PYTEST_ARGS} test_docker.py
fi

echo "--- ✅ All tests passed! ---"