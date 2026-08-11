import json
import os
import subprocess
import time

import pytest
import testinfra

# --- Configuration ---
MAJOR_VER = os.getenv("VERSION").split(".")[0]
DOCKER_REPO = os.getenv("DOCKER_REPOSITORY")
IMG_TAG = os.getenv("TAG")
IMAGE = f"{DOCKER_REPO}/percona-distribution-postgresql-custom:{IMG_TAG}"

REQUIRED_LABEL_MAINTAINER = os.getenv(
    "PPG_LABEL_MAINTAINER", "Percona Development <info@percona.com>"
)
REQUIRED_LABEL_VENDOR = os.getenv("PPG_LABEL_VENDOR", "Percona")
REQUIRED_LABEL_NAME_PREFIX = "Percona "
EXPECTED_LABEL_NAME_POSTGRESQL = os.getenv(
    "PPG_LABEL_NAME_POSTGRESQL", "Percona Distribution for PostgreSQL"
)
REQUIRED_LABEL_KEYS = (
    "name",
    "vendor",
    "version",
    "release",
    "summary",
    "description",
    "maintainer",
)
RED_HAT_TRADEMARK_FORBIDDEN = ("Red Hat", "RHEL", "RedHat")

# Registry manifest media types must be OCI-only: no Docker-format
# (vnd.docker) entries, and no mixing of OCI and Docker formats.
EXPECTED_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
EXPECTED_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
# The manifest list/index is published under the base tag, without the
# per-architecture "-arm64" suffix this test may be running under.
_BASE_TAG = IMG_TAG[:-6] if IMG_TAG.endswith("-arm64") else IMG_TAG
MANIFEST_IMAGE = f"{IMAGE.rsplit(':', 1)[0]}:{_BASE_TAG}"


# --- Fixtures ---
@pytest.fixture(scope="session")
def host(request):
    """Session-wide container. Used for internal filesystem and DB checks."""
    container_name = f"PG_TEST_{MAJOR_VER}"

    # Cleanup previous runs
    subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)

    run_cmd = [
        "docker",
        "run",
        "--name",
        container_name,
        "-e",
        "POSTGRES_PASSWORD=password",
        "-d",
        IMAGE,
    ]
    subprocess.check_output(run_cmd)

    # Wait for the container to actually be ready
    time.sleep(2)

    yield testinfra.get_host("docker://" + container_name)
    subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)


# --- Helper Functions ---
@pytest.fixture(scope="session")
def image_labels():
    """Fixture to pull image and return labels once per session."""
    subprocess.run(["docker", "pull", IMAGE], check=True, capture_output=True)
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{json .Config.Labels}}", IMAGE],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout) if result.stdout.strip() else {}


@pytest.fixture(scope="session")
def image_manifest():
    """Fixture to fetch the registry manifest list/index once per session."""
    result = subprocess.run(
        ["docker", "manifest", "inspect", MANIFEST_IMAGE],
        env={**os.environ, "DOCKER_CLI_EXPERIMENTAL": "enabled"},
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


def test_ppg_postgres_image_labels(image_labels):
    """Use the image_labels fixture for testing."""
    # Now 'image_labels' is just a dictionary you can assert against
    assert image_labels.get("vendor") == REQUIRED_LABEL_VENDOR

    # 1. Check all required keys exist and are not empty
    for key in REQUIRED_LABEL_KEYS:
        assert image_labels.get(key), f"Required label '{key}' is missing or empty"

    # 2. Trademark Compliance
    for key in ("name", "vendor", "maintainer"):
        val = image_labels.get(key, "")
        for forbidden in RED_HAT_TRADEMARK_FORBIDDEN:
            assert forbidden not in val, (
                f"Label '{key}' contains forbidden trademark '{forbidden}'"
            )

    # 3. Value Accuracy
    assert image_labels.get("vendor") == REQUIRED_LABEL_VENDOR
    assert image_labels.get("maintainer") == REQUIRED_LABEL_MAINTAINER
    assert image_labels.get("name") == EXPECTED_LABEL_NAME_POSTGRESQL
    assert image_labels.get("name").startswith(REQUIRED_LABEL_NAME_PREFIX)


def test_ppg_postgres_image_manifest_media_types(image_manifest):
    """Verify the manifest list/index and every platform manifest are
    OCI-only: no vnd.docker entries and no mixing of OCI and Docker types."""
    top_level_media_type = image_manifest.get("mediaType")
    assert top_level_media_type == EXPECTED_INDEX_MEDIA_TYPE, (
        f"Top-level mediaType for {MANIFEST_IMAGE} must be "
        f"'{EXPECTED_INDEX_MEDIA_TYPE}', got '{top_level_media_type}'"
    )

    platform_manifests = image_manifest.get("manifests", [])
    assert platform_manifests, f"No platform manifests found for {MANIFEST_IMAGE}"

    non_oci_entries = [
        f"{entry.get('platform', {}).get('architecture')}={entry.get('mediaType')}"
        for entry in platform_manifests
        if entry.get("mediaType") != EXPECTED_MANIFEST_MEDIA_TYPE
    ]
    assert not non_oci_entries, (
        f"Non-OCI platform manifest(s) found for {MANIFEST_IMAGE}: "
        f"{', '.join(non_oci_entries)}. All platform manifests must use "
        f"'{EXPECTED_MANIFEST_MEDIA_TYPE}'."
    )


def test_ppg_postgres_licenses(host):
    """Verify license information exists inside the container."""
    license_path = host.file("/licenses")

    assert license_path.exists, "/licenses path is missing in the image"

    if license_path.is_directory:
        # Check that the directory is not empty
        files = host.check_output("ls -A /licenses")
        assert len(files.strip()) > 0, "/licenses directory is empty"
    else:
        # If it's a file, ensure it's not empty
        assert license_path.size > 0, "/licenses file is empty"


def test_container_user_non_root(host):
    """Compliance: Ensure the container doesn't run as root by default."""
    current_user = host.user().name
    assert current_user != "root", f"Security failure: Container is running as {current_user}"
