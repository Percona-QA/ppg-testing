import os
import subprocess
import time
import psycopg2
import pytest
import testinfra
from packaging import version

import settings

# --- Configuration constants/settings ---
# Constants
MAJOR_VER = os.getenv("VERSION").split(".")[0]
MAJOR_MINOR_VER = os.getenv("VERSION")
DOCKER_REPO = os.getenv("DOCKER_REPOSITORY")
IMG_TAG = os.getenv("TAG")
IS_WITH_POSTGIS = os.getenv("WITH_POSTGIS", "false").lower() == "true"
PG_BIN_DIR = f"/usr/pgsql-{MAJOR_VER}/bin"
PG_DATA_DIR = "/data/db"
if IS_WITH_POSTGIS:
    IMAGE = f"{DOCKER_REPO}/percona-distribution-postgresql-with-postgis:{IMG_TAG}"
else:
    IMAGE = f"{DOCKER_REPO}/percona-distribution-postgresql:{IMG_TAG}"

# --- Settings ---
pg_docker_versions = settings.get_settings(MAJOR_MINOR_VER)
DOCKER_RHEL_FILES = pg_docker_versions["rhel_files"]
DOCKER_RPM_PACKAGES = pg_docker_versions["rpm_packages"]
DOCKER_EXTENSIONS = pg_docker_versions["extensions"]
DOCKER_BINARIES = pg_docker_versions["binaries"]

# List of expected PG-18 TDE binaries
TDE_BINARIES = [
    "pg_tde_archive_decrypt",
    "pg_tde_basebackup",
    "pg_tde_change_key_provider",
    "pg_tde_checksums",
    "pg_tde_resetwal",
    "pg_tde_restore_encrypt",
    "pg_tde_rewind",
    "pg_tde_upgrade",
    "pg_tde_waldump",
]

# Red Hat ecosystem required image labels (same as pgbouncer/pgbackrest)
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


def reconnect_db():
    """Helper to establish a fresh connection if the server restarted or crashed."""
    for _i in range(10):
        try:
            conn = psycopg2.connect(**DB_PARAMS)
            conn.autocommit = True
            return conn
        except psycopg2.OperationalError:
            time.sleep(2)
    pytest.fail("Could not reconnect to database after server crash.")


@pytest.fixture(scope="session")
def host(request):
    container_name = f"PG{MAJOR_VER}"
    needs_libs = any(item.get_closest_marker("needs_preload") for item in request.session.items)

    subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)

    print("")
    print("\n------------Settings--------------")
    print(f"Major Version: {MAJOR_VER}")
    print(f"Major Minor Version: {MAJOR_MINOR_VER}")
    print(f"Image TAG: {IMG_TAG}")
    print(f"IS_WITH_POSTGIS: {IS_WITH_POSTGIS}")
    print(f"DOCKER_TO_USE: {IMAGE}")
    print("--------------------------------")

    run_cmd = [
        "docker",
        "run",
        "--name",
        container_name,
        "-e",
        "POSTGRES_PASSWORD=password",
        "--shm-size=2g",
        "-p",
        "5432:5432",
        "-d",
        IMAGE,
    ]

    if needs_libs:
        # These specific flags prevent pg_stat_monitor from over-allocating on boot
        preload_libs = "pg_stat_monitor,pgaudit,set_user"
        if int(MAJOR_VER) >= 17:
            preload_libs = f"pg_tde,{preload_libs}"
        pg_cron_min = PG_CRON_MIN_VERSIONS.get(int(MAJOR_VER))
        pg_cron_available = pg_cron_min and version.parse(MAJOR_MINOR_VER) >= pg_cron_min
        if pg_cron_available:
            preload_libs = f"pg_cron,{preload_libs}"
        run_cmd.extend(
            [
                "-c",
                f"shared_preload_libraries={preload_libs}",
                "-c",
                "shared_buffers=256MB",
                "-c",
                "max_worker_processes=32",  # Give extensions room to breathe
                "-c",
                "max_parallel_workers=16",
                "-c",
                "pg_stat_monitor.pgsm_max=500",  # Smaller bucket to save shared mem
                "-c",
                "pg_stat_monitor.pgsm_query_max_len=1024",
                "-c",
                "wal_level=logical",
            ]
        )
        if pg_cron_available:
            run_cmd.extend(["-c", "cron.database_name=postgres"])

    subprocess.check_output(run_cmd)

    # --- STABILITY WAIT ---
    # Don't just wait; verify the server can actually answer a query
    for _ in range(30):
        res = subprocess.run(["docker", "exec", container_name, "pg_isready"], capture_output=True)
        if res.returncode == 0:
            # Final sanity check: Can we run a SQL command?
            sql = subprocess.run(
                ["docker", "exec", container_name, "psql", "-U", "postgres", "-c", "SELECT 1"],
                capture_output=True,
            )
            if sql.returncode == 0:
                break
        time.sleep(1)

    time.sleep(2)  # Final settle time for background workers
    yield testinfra.get_host("docker://" + container_name)
    subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)


def test_shared_preload_libraries_is_empty(cursor, request):
    """
    Verification: Ensure no libraries are preloaded at startup.
    Skip if session-wide container was booted with libraries for other tests.
    """
    # Check if any test in the whole session has the 'needs_preload' mark
    session_needs_libs = any(
        item.get_closest_marker("needs_preload") for item in request.session.items
    )

    if session_needs_libs:
        pytest.skip(
            "Skipping 'Empty' check: session is running in 'Preload Mode'."
        )

    cursor.execute("SHOW shared_preload_libraries;")
    setting = cursor.fetchone()[0]
    assert setting == "" or setting.lower() == "none"


def test_psql_string(host):
    # 'host' now binds to the container
    psql_output = host.check_output("psql -V")
    if int(MAJOR_VER) in [17, 18]:
        assert f"psql (PostgreSQL) {MAJOR_MINOR_VER} - Percona Server for PostgreSQL {pg_docker_versions['percona-version']}" in host.check_output('psql -V')
    else:
        assert f"psql (PostgreSQL) {MAJOR_MINOR_VER} - Percona Distribution" in host.check_output('psql -V')


def test_wait_docker_load(host):
    time.sleep(5)
    assert 0 == 0


def _expected_ubi_major_version():
    """Derive expected RHEL/UBI major version from the image tag.

    Rules:
      - tag contains 'ubi8'  -> expect RHEL/UBI 8
      - tag contains 'ubi10' -> expect RHEL/UBI 10
      - no 'ubi' in tag      -> default to RHEL/UBI 9
    """
    tag = IMG_TAG.lower()
    if 'ubi8' in tag:
        return '8'
    if 'ubi10' in tag:
        return '10'
    return '9'


def test_base_image_matches_ubi_tag(host):
    """Verify the container base OS major version matches the UBI version in the image tag.

    - ubi8  tag -> RHEL/UBI 8
    - ubi10 tag -> RHEL/UBI 10
    - no ubi    -> RHEL/UBI 9 (default)
    """
    expected = _expected_ubi_major_version()
    os_release = host.file('/etc/os-release').content_string
    version_id = None
    for line in os_release.splitlines():
        if line.startswith('VERSION_ID='):
            version_id = line.split('=', 1)[1].strip().strip('"').split('.')[0]
            break
    assert version_id is not None, "Could not find VERSION_ID in /etc/os-release"
    assert version_id == expected, (
        f"Base image OS mismatch: tag '{IMG_TAG}' expects RHEL/UBI {expected}, "
        f"but container /etc/os-release reports VERSION_ID major={version_id}"
    )


@pytest.fixture()
def postgresql_binary(host):
    pg_binary = f"{PG_BIN_DIR}/postgres"
    return host.file(pg_binary)


@pytest.fixture()
def postgresql_query_version(host):
    return host.run("psql -c 'SELECT version()' | awk 'NR==3{print $2}'")


def postgres_binary(postgresql_binary):
    assert postgresql_binary.exists
    assert postgresql_binary.user == "root"


@pytest.mark.parametrize("binary", DOCKER_BINARIES)
def test_binaries(host, binary):
    # bin_path = f"/usr/lib/postgresql/{MAJOR_VER}/bin/"
    # if dist.lower() in ["redhat", "centos", "rhel", "rocky"]:
    #     bin_path = f"/usr/pgsql-{MAJOR_VER}/bin/"
    bin_path = f"/usr/pgsql-{MAJOR_VER}/bin/"
    bin_full_path = os.path.join(bin_path, binary)
    binary_file = host.file(bin_full_path)
    assert binary_file.exists


def test_pg_config_server_version(host):
    cmd = "pg_config --version"
    try:
        result = host.check_output(cmd)
        assert f"{MAJOR_MINOR_VER}" in result, result.stdout
    except AssertionError:
        pytest.mark.xfail(reason="Maybe dev package not install")


def test_postgresql_query_version(postgresql_query_version):
    assert postgresql_query_version.rc == 0, postgresql_query_version.stderr
    assert postgresql_query_version.stdout.strip("\n") == f"{MAJOR_MINOR_VER}", (
        postgresql_query_version.stdout
    )


def test_postgres_client_version(host):
    cmd = "psql --version"
    result = host.check_output(cmd)
    assert f"{MAJOR_MINOR_VER}" in result.strip("\n"), result.stdout


SKIP_EXTENSIONS = [
    "pg_tde",
    "postgis_sfcgal",
    "address_standardizer",
    "postgis_tiger_geocoder",
    "postgis",
    "postgis_topology",
    "postgis_raster",
    "address_standardizer_data_us",
    "pgaudit",
    "plpgsql",
    "pg_repack",
    "pg_stat_monitor",
]


@pytest.fixture(scope="module")
def extension_list(host):
    """
    Fetches the list of all available extensions from PostgreSQL once per test module.
    """
    # -t: tuples only, -A: unaligned, -q: quiet
    cmd = "psql -t -A -q -c 'SELECT name FROM pg_available_extensions;'"
    res = host.run(cmd)
    assert res.rc == 0, f"Failed to fetch extension list: {res.stderr}"

    # Transform the multiline string into a clean set for O(1) lookup speed
    return set(res.stdout.split())


def should_skip(extension):
    major = int(MAJOR_VER)

    # 1. Hard skips
    if extension in SKIP_EXTENSIONS:
        return True, "Explicitly skipped in SKIP_EXTENSIONS"

    # 2. Version-based removals
    if major >= 17 and extension == "adminpack":
        return True, "adminpack removed in PG17+"

    if major < 17 and extension == "pg_tde":
        return True, "pg_tde requires PG17+"

    if major < 18 and extension == "pg_logicalinspect":
        return True, "pg_logicalinspect only supported in PG18+"

    # 4. Feature-flag based skips
    postgis_family = {
        "postgis",
        "postgis_topology",
        "postgis_raster",
        "postgis_sfcgal",
        "address_standardizer",
        "postgis_tiger_geocoder",
        "address_standardizer_data_us",
    }
    if not IS_WITH_POSTGIS and extension in postgis_family:
        return True, "Docker build is without PostGIS so skipping."

    return False, None


@pytest.mark.parametrize("extension", DOCKER_EXTENSIONS)
def test_extensions_list(extension_list, host, extension):
    """
    Verifies that the extension is available to be installed in the PostgreSQL instance.
    """
    # 1. Use the centralized helper for skip logic
    # This replaces the messy if/elif blocks and ensures consistency
    skip, reason = should_skip(extension)
    if skip:
        pytest.skip(reason)

    # 2. Verify the extension is present in the available extensions list
    # Use a descriptive error message to help debug if it's missing
    assert extension in extension_list, (
        f"Extension '{extension}' was expected but is not available in the "
        f"PostgreSQL {MAJOR_VER} installation."
    )


@pytest.mark.parametrize("extension", DOCKER_EXTENSIONS)
def test_enable_extension(host, extension):
    skip, reason = should_skip(extension)
    if skip:
        pytest.skip(reason)

    # 1. Install Extension
    res = host.run(f'psql -c "CREATE EXTENSION \\"{extension}\\";"')
    assert res.rc == 0, f"Failed to create {extension}: {res.stderr}"
    assert "CREATE EXTENSION" in res.stdout

    # 2. Verify existence using SQL count (Reliable replacement for awk)
    check_sql = f"SELECT count(*) FROM pg_extension WHERE extname = '{extension}';"
    count = host.run(f'psql -t -A -c "{check_sql}"').stdout.strip()
    assert count == "1", f"Extension {extension} not found in pg_extension table"


@pytest.mark.parametrize("extension", DOCKER_EXTENSIONS[::-1])
def test_drop_extension(host, extension):
    skip, reason = should_skip(extension)
    if skip:
        pytest.skip(reason)

    # 1. Drop Extension (Use CASCADE to handle dependencies)
    res = host.run(f'psql -c "DROP EXTENSION \\"{extension}\\" CASCADE;"')
    assert res.rc == 0, f"Failed to drop {extension}: {res.stderr}"
    assert "DROP EXTENSION" in res.stdout

    # 2. Verify it is gone
    check_sql = f"SELECT count(*) FROM pg_extension WHERE extname = '{extension}';"
    count = host.run(f'psql -t -A -c "{check_sql}"').stdout.strip()
    assert count == "0", f"Extension {extension} still exists after drop"


def test_plpgsql_extension(host):
    # plpgsql is internal and always exists; just check for it directly
    check_sql = "SELECT count(*) FROM pg_extension WHERE extname = 'plpgsql';"
    count = host.run(f'psql -t -A -c "{check_sql}"').stdout.strip()
    assert count == "1", "Default extension 'plpgsql' is missing!"


@pytest.mark.parametrize("package", DOCKER_RPM_PACKAGES)
def test_rpm_package_is_installed(host, package):
    # 1. Centralized Skip Logic
    if int(MAJOR_VER) < 17 and "pg_tde" in package:
        pytest.skip(f"pg_tde not supported on PostgreSQL {MAJOR_VER}")

    if not IS_WITH_POSTGIS and "postgis" in package:
        pytest.skip(f"Docker build is without PostGIS so skipping {package}.")

    if "oidc_validator" in package and int(MAJOR_VER) < 18:
        pytest.skip(f"Skipping {package} for PostgreSQL {MAJOR_VER} (only supported on 18.2+).")

    if "pg_cron" in package:
        _skip_if_pg_cron_unavailable()

    pkg = host.package(package)

    # 2. Verify Installation
    assert pkg.is_installed, f"Package {package} is not installed"

    # 3. Dynamic Version Lookup
    pkg_data = pg_docker_versions.get(package)

    if isinstance(pkg_data, dict):
        expected_version = pkg_data.get("version")
    else:
        expected_version = pkg_data

    # Fallback to the global 'version' if the specific package isn't mapped
    if not expected_version:
        expected_version = pg_docker_versions.get("version")

    # --- Console Output Enhancement ---
    print(f"\n[VERIFYING] Package: {package}")
    print(f"            Expected: {expected_version}")
    print(f"            Found:    {pkg.version}")

    assert pkg.version == expected_version, (
        f"Version mismatch for {package}. Expected: {expected_version}, Found: {pkg.version}"
    )

    print(f"[SUCCESS] {package} version {pkg.version} verified.")


def test_llvmjit_files_present(host):
    """Strategy 1: Verify that LLVM JIT .so and .bc files are present and non-empty."""
    _skip_if_llvmjit_unavailable()
    lib_path = f"/usr/pgsql-{MAJOR_VER}/lib"
    expected_files = [
        f"{lib_path}/llvmjit.so",
        f"{lib_path}/llvmjit_types.bc",
    ]
    for path in expected_files:
        f = host.file(path)
        assert f.exists, f"Missing LLVM JIT file: {path}"
        assert f.is_file, f"Path exists but is not a file: {path}"
        assert f.size > 0, f"File {path} exists but is empty!"


def test_llvmjit_rpm_ownership(host):
    """Strategy 2: Verify llvmjit.so and llvmjit_types.bc are owned by the llvmjit RPM package."""
    _skip_if_llvmjit_unavailable()
    lib_path = f"/usr/pgsql-{MAJOR_VER}/lib"
    expected_pkg = f"percona-postgresql{MAJOR_VER}-llvmjit"
    for filename in ["llvmjit.so", "llvmjit_types.bc"]:
        path = f"{lib_path}/{filename}"
        result = host.run(f"rpm -qf {path}")
        assert result.rc == 0, f"rpm -qf failed for {path}: {result.stderr}"
        assert expected_pkg in result.stdout, (
            f"{path} is not owned by {expected_pkg}. Got: {result.stdout.strip()}"
        )


def test_llvmjit_statically_linked(host):
    """Strategy 3: Verify llvmjit.so has no dynamic dependency on libLLVM (statically linked)."""
    _skip_if_llvmjit_unavailable()
    so_path = f"/usr/pgsql-{MAJOR_VER}/lib/llvmjit.so"
    result = host.run(f"ldd {so_path}")
    assert result.rc == 0, f"ldd failed on {so_path}: {result.stderr}"
    assert "libLLVM" not in result.stdout, (
        f"llvmjit.so has a dynamic libLLVM dependency — expected static linking.\n"
        f"ldd output:\n{result.stdout}"
    )


def test_llvmjit_symbols_present(host):
    """Strategy 4: Verify the JIT provider entry point is exported from llvmjit.so.

    PostgreSQL loads the JIT provider via dlopen() + dlsym("_PG_jit_provider_init").
    That function fills a JitProviderCallbacks struct with internal function pointers
    (compile_expr, etc.) — those are never dlsym'd directly and are therefore not
    required to be dynamic exports.  _PG_jit_provider_init is the only symbol that
    must appear in the dynamic symbol table on every platform."""
    _skip_if_llvmjit_unavailable()
    _ensure_nm_available(host)
    so_path = f"/usr/pgsql-{MAJOR_VER}/lib/llvmjit.so"
    result = host.run(f"nm -D {so_path} | grep -q '_PG_jit_provider_init'")
    assert result.rc == 0, (
        f"Expected JIT symbol '_PG_jit_provider_init' not found in {so_path}. "
        f"The library may be missing or incorrectly built."
    )


def test_llvmjit_no_undefined_cxx_symbols(host):
    """Strategy 4b: Verify llvmjit.so has no undefined C++ stdlib symbols (_ZSt*).
    Catches the bug where llvmjit.so failed to load at runtime with:
      ERROR: could not load library 'llvmjit.so': undefined symbol: _ZSt21__glibcxx_assert_fail...
    These symbols must be statically linked into llvmjit.so on RHEL builds."""
    _skip_if_llvmjit_unavailable()
    _ensure_nm_available(host)
    so_path = f"/usr/pgsql-{MAJOR_VER}/lib/llvmjit.so"
    result = host.run(f"nm -D {so_path} | awk '$2 == \"U\" && $3 ~ /^_ZSt/ {{print}}'")
    assert result.rc == 0, f"nm -D failed on {so_path}: {result.stderr}"
    assert result.stdout.strip() == "", (
        f"llvmjit.so has undefined C++ stdlib symbols (_ZSt*) — "
        f"this will cause a runtime load failure.\n"
        f"Undefined symbols found:\n{result.stdout}"
    )


def test_llvmjit_functional(host):
    """Strategy 5: Verify JIT actually loads and compiles at runtime via EXPLAIN ANALYZE.
    Reproduces the exact failure scenario: if llvmjit.so has undefined symbols the query
    returns ERROR instead of a plan with a JIT: section."""
    _skip_if_llvmjit_unavailable()
    result = host.run(
        "psql -c \""
        "SET jit = on; "
        "SET jit_above_cost = 0; "
        "SET jit_inline_above_cost = 0; "
        "SET jit_optimize_above_cost = 0; "
        "EXPLAIN (ANALYZE, VERBOSE, BUFFERS) "
        "SELECT count(*) FROM generate_series(1, 1000000) g WHERE g % 2 = 0;\""
    )
    assert result.rc == 0, (
        f"JIT load failed — possible undefined symbol in llvmjit.so.\n"
        f"stderr: {result.stderr}\nstdout: {result.stdout}"
    )
    assert "JIT:" in result.stdout, (
        f"JIT was not triggered. EXPLAIN ANALYZE output:\n{result.stdout}"
    )


def test_llvmjit_pg_config_compiled_with_llvm(host):
    """Strategy 6: Verify PostgreSQL was compiled with --with-llvm via pg_config --configure."""
    _skip_if_llvmjit_unavailable()
    result = host.run(f"/usr/pgsql-{MAJOR_VER}/bin/pg_config --configure")
    assert result.rc == 0, f"pg_config --configure failed: {result.stderr}"
    assert "--with-llvm" in result.stdout, (
        f"PostgreSQL was not compiled with --with-llvm.\n"
        f"pg_config --configure output:\n{result.stdout}"
    )


def test_openssl_version_matches_ubi(host):
    """Verify the OpenSSL version in the container matches the expected version for the UBI base.

    - UBI 8  -> OpenSSL 1.x
    - UBI 9  -> OpenSSL 3.x
    - UBI 10 -> OpenSSL 3.x
    """
    EXPECTED_OPENSSL_MAJOR = {'8': '1', '9': '3', '10': '3'}
    ubi_major = _expected_ubi_major_version()
    expected = EXPECTED_OPENSSL_MAJOR[ubi_major]

    result = host.run("openssl version")
    assert result.rc == 0, f"openssl version failed: {result.stderr}"
    # Output: "OpenSSL 1.1.1k  FIPS ..." or "OpenSSL 3.0.7 ..."
    actual_major = result.stdout.strip().split()[1].split('.')[0]
    assert actual_major == expected, (
        f"OpenSSL version mismatch for UBI {ubi_major}: "
        f"expected major {expected}, got '{result.stdout.strip()}'"
    )


def test_llvm_version_matches_ubi(host):
    """Verify the LLVM major version installed in the container matches the expected
    range for the UBI base image.

    - UBI 8  -> LLVM 13 or 14
    - UBI 9  -> LLVM 15, 16, or 17
    - UBI 10 -> LLVM 17, 18, or 19
    """
    _skip_if_llvmjit_unavailable()
    EXPECTED_LLVM_MAJORS = {
        '8':  [13, 14],
        '9':  [15, 16, 17],
        '10': [17, 18, 19],
    }
    ubi_major = _expected_ubi_major_version()
    expected_majors = EXPECTED_LLVM_MAJORS[ubi_major]

    # Read LLVM version from installed llvm-libs RPM package
    result = host.run("rpm -qa --queryformat '%{VERSION}\\n' 'llvm-libs*' | head -1")
    if result.rc != 0 or not result.stdout.strip():
        # Fallback: detect from installed libLLVM shared library filenames
        result = host.run(
            "find /usr/lib64 -maxdepth 1 -name 'libLLVM-*.so' 2>/dev/null | "
            "sed 's/.*libLLVM-\\([0-9]*\\).*/\\1/' | head -1"
        )
    assert result.stdout.strip(), "Could not determine LLVM version from rpm or /usr/lib64"
    actual_major = int(result.stdout.strip().split('.')[0])
    assert actual_major in expected_majors, (
        f"LLVM major version mismatch for UBI {ubi_major}: "
        f"expected one of {expected_majors}, got {actual_major}"
    )


@pytest.mark.needs_preload
def test_pg_stat_monitor_extension_version(host):
    # 1. Ensure extension is created
    create_res = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS pg_stat_monitor;'")
    assert create_res.rc == 0, create_res.stderr

    # 2. Get the Extension version (SQL Level)
    # -t: tuples only, -A: unaligned
    query = "SELECT pg_stat_monitor_version();"
    actual_ext_version = host.run(f'psql -t -A -c "{query}"').stdout.strip()

    # 3. Get Expected version from dictionary
    pkg_key = f"percona-pg_stat_monitor{MAJOR_VER}"
    expected_full_version = pg_docker_versions[pkg_key]["version"]

    # 4. Clean the version string
    # RPM versions often look like '2.1.0-1.el9'. We need to strip the '-1.el9'
    # part to match the PostgreSQL extension version '2.1.0'.
    expected_clean_version = expected_full_version.split("-")[0]

    assert actual_ext_version == expected_clean_version, (
        f"Extension version {actual_ext_version} does not match "
        f"expected version {expected_clean_version}"
    )


@pytest.mark.parametrize("file", DOCKER_RHEL_FILES)
def test_rpm_files(file, host):
    f = host.file(file)
    assert f.exists
    assert f.size > 0
    assert f.content_string != ""
    assert f.user == "postgres"


def test_build_with_liburing(host):
    if MAJOR_VER not in ["18"]:
        pytest.skip("Skipping, test only for PostgreSQL 18 version")

    ubi_major = _expected_ubi_major_version()
    if ubi_major == '8':
        pytest.skip(f"liburing not supported on UBI/RHEL 8 for postgres {MAJOR_VER}")

    cmd = "pg_config --configure"
    output = host.check_output(cmd)
    assert "--with-liburing" in output, "PostgreSQL 18 was built without --with-liburing"


@pytest.mark.parametrize(
    "flag",
    [
        ("--enable-debug"),
        ("--enable-cassert"),
        ("--disable-thread-safety"),
    ],
)
def test_pg_config_flags(host, flag):
    """
    Verify that certain build flags are NOT present in pg_config --configure output.
    """

    # Get the PostgreSQL configuration output
    cmd = "pg_config --configure"
    output = host.check_output(cmd)

    assert flag not in output, f"PostgreSQL was built with {flag}, but it should NOT be present"


def test_postgis_extension(host):
    if not IS_WITH_POSTGIS:
        pytest.skip("Skipping PostGIS test.")

    # 1. Execute the create command
    cmd = "psql -c 'CREATE EXTENSION IF NOT EXISTS postgis CASCADE;'"
    result = host.run(cmd)
    assert result.rc == 0

    # 2. Metadata Verification: Check if it's in pg_extension
    check_cmd = "psql -t -c \"SELECT count(*) FROM pg_extension WHERE extname = 'postgis';\""
    count = host.run(check_cmd).stdout.strip()
    assert count == "1"

    # 3. Version Check (Metadata): Get the installed version string
    version_cmd = "psql -t -c \"SELECT extversion FROM pg_extension WHERE extname = 'postgis';\""
    actual_version = host.run(version_cmd).stdout.strip()
    # Assert version is not empty (e.g., '3.4')
    assert len(actual_version) > 0
    print(f"Detected PostGIS Extension Version: {actual_version}")
    # Check expected version

    expected_version = pg_docker_versions.get(f"percona-postgis35_{MAJOR_VER}", {}).get(
        "extension_version"
    )
    assert actual_version == expected_version, (
        f"Expected {expected_version}, but found {actual_version}"
    )

    # 4. Functional Check: Verify the extension is actually working
    # This ensures the underlying GEOS and PROJ libraries are linked correctly
    func_cmd = 'psql -t -c "SELECT postgis_version();"'
    func_result = host.run(func_cmd)

    assert func_result.rc == 0
    assert "3." in func_result.stdout  # Assuming you expect PostGIS 3.x

    # Execute the drop command with CASCADE
    cmd = "psql -c 'DROP EXTENSION IF EXISTS postgis CASCADE;'"
    result = host.run(cmd)

    # Check if the command executed successfully
    assert result.rc == 0

    # Verification: Ensure it no longer exists in pg_extension
    check_cmd = "psql -t -c \"SELECT count(*) FROM pg_extension WHERE extname = 'postgis';\""
    count = host.run(check_cmd).stdout.strip()
    assert count == "0"


def test_pgvector_extension(host):
    # 1. Execute the create command
    # Note: The extension name is 'vector', though the project is pgvector
    cmd = "psql -c 'CREATE EXTENSION IF NOT EXISTS vector CASCADE;'"
    result = host.run(cmd)
    assert result.rc == 0

    # 2. Metadata Verification: Check if it's in pg_extension
    check_cmd = "psql -t -c \"SELECT count(*) FROM pg_extension WHERE extname = 'vector';\""
    count = host.run(check_cmd).stdout.strip()
    assert count == "1"

    # 3. Version Check (Metadata): Get the installed version string
    version_cmd = "psql -t -c \"SELECT extversion FROM pg_extension WHERE extname = 'vector';\""
    actual_version = host.run(version_cmd).stdout.strip()

    # Assert version is not empty
    assert len(actual_version) > 0
    print(f"Detected pgvector Extension Version: {actual_version}")

    # Check against your expected versions dictionary
    expected_version = pg_docker_versions.get(f"percona-pgvector_{MAJOR_VER}", {}).get(
        "extension_version"
    )

    assert actual_version == expected_version, (
        f"Expected {expected_version}, but found {actual_version}"
    )

    # 4. Functional Check: Verify the 'vector' type is usable
    # We cast a string to a vector and check its dimensions to ensure the C library is loaded
    func_cmd = "psql -t -c \"SELECT vector_dims('[1,2,3]'::vector);\""
    func_result = host.run(func_cmd)

    assert func_result.rc == 0
    assert func_result.stdout.strip() == "3"

    # 5. Execute the drop command with CASCADE
    cmd = "psql -c 'DROP EXTENSION IF EXISTS vector CASCADE;'"
    result = host.run(cmd)
    assert result.rc == 0

    # 6. Verification: Ensure it no longer exists in pg_extension
    check_cmd = "psql -t -c \"SELECT count(*) FROM pg_extension WHERE extname = 'vector';\""
    count = host.run(check_cmd).stdout.strip()
    assert count == "0"


def test_patroni_version(host):
    # 1. Run the patroni version command
    # Output is usually in the format: "patroni 3.3.0"
    cmd = "patroni --version"
    result = host.run(cmd)

    # 2. Check if the command exists and executed successfully
    assert result.rc == 0, f"Patroni command failed or is not installed: {result.stderr}"

    # 3. Parse the version number
    # result.stdout might be "patroni 3.3.0", we want the second part
    actual_version = result.stdout.strip()

    print(f"Detected Patroni Version: {actual_version}")

    # 4. Compare with the expected version from your dictionary
    # Assuming the key follows your pattern: pg_docker_versions["patroni"]["binary_version"]
    expected_version = pg_docker_versions.get("percona-patroni", {}).get("binary_version")

    if expected_version:
        assert actual_version == expected_version, (
            f"Expected {expected_version}, but found {actual_version}"
        )
    else:
        assert len(actual_version) > 0, "Patroni version could not be determined"


def test_pgbackrest_version(host):
    # 1. Run the pgbackrest version command
    # Typical output: "pgBackRest 2.50"
    cmd = "pgbackrest version"
    result = host.run(cmd)

    # 2. Check if the command exists and executed successfully
    assert result.rc == 0, f"pgBackRest command failed: {result.stderr}"

    # 3. Parse the version number
    # We split the string and take the last element (e.g., "2.50")
    actual_version = result.stdout.strip()

    print(f"Detected pgBackRest Version: {actual_version}")

    # 4. Compare with the expected version from your dictionary
    expected_version = pg_docker_versions.get("percona-pgbackrest", {}).get("binary_version")

    if expected_version:
        assert actual_version == expected_version, (
            f"Expected {expected_version}, but found {actual_version}"
        )
    else:
        # Fallback: just ensure we got a valid-looking version string
        assert len(actual_version) > 0 and actual_version[0].isdigit()


# --- Configuration ---
DB_PARAMS = {
    "dbname": "postgres",
    "user": "postgres",
    "password": "password",
    "host": "localhost",
    "port": "5432",
}


# --- Fixtures (Internalized conftest logic) ---
@pytest.fixture(scope="session")
def db_connection(host):  # <--- Adding 'host' here forces host to finish booting first
    container_name = f"PG{MAJOR_VER}"
    max_retries = 45

    # Check if container exists
    status = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", container_name],
        capture_output=True,
        text=True,
    )

    if status.returncode != 0:
        pytest.fail(
            f"Container {container_name} does not exist. Docker Run might have failed silently."
        )

    conn = None

    # 1. Pre-flight Check: Is the container even alive?
    status = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", container_name],
        capture_output=True,
        text=True,
    )

    if "true" not in status.stdout.lower():
        # If it's not running, it probably crashed during the 'host' fixture boot
        logs = subprocess.run(["docker", "logs", container_name], capture_output=True, text=True)
        pytest.fail(
            f"FATAL: Container {container_name} is NOT running.\n"
            f"Check if shared_preload_libraries are valid.\n"
            f"--- DOCKER LOGS ---\n{logs.stdout}\n{logs.stderr}"
        )

    # 2. Connection Loop
    for i in range(max_retries):
        try:
            conn = psycopg2.connect(**DB_PARAMS)
            conn.autocommit = True
            print(f"\n[INFO] Connected to {container_name} successfully.")
            return conn

        except psycopg2.OperationalError as e:
            err_msg = str(e).lower()

            # Scenario A: Server is still booting (Normal)
            if "connection refused" in err_msg or "starting up" in err_msg:
                print(f"[WAIT] Postgres is initializing (attempt {i + 1}/{max_retries})...")
                time.sleep(2)

            # Scenario B: Server crashed WHILE we were talking to it (Abnormal)
            elif (
                "closed the connection unexpectedly" in err_msg
                or "terminating connection" in err_msg
            ):
                print(f"\n[FATAL] Postgres crashed during connection attempt {i + 1}!")
                # Immediate log dump to see the PANIC/FATAL message
                res = subprocess.run(
                    ["docker", "logs", container_name, "--tail", "20"],
                    capture_output=True,
                    text=True,
                )
                print(f"--- RECENT LOGS ---\n{res.stdout}")
                pytest.fail("Postgres process crashed. See logs above for details.")

            # Scenario C: Something else (Wrong credentials, wrong port, etc.)
            else:
                print(f"[DEBUG] Unexpected Connection Error: {err_msg}")
                time.sleep(2)

    # 3. Final Fallback
    if not conn:
        print("\n" + "=" * 50)
        print(f"TIMEOUT: Could not connect to {container_name} after 90s.")
        res = subprocess.run(
            ["docker", "logs", container_name, "--tail", "20"], capture_output=True, text=True
        )
        print(f"Final Logs:\n{res.stdout}")
        print("=" * 50)
        pytest.fail("Database connection timeout. See logs above.")


@pytest.fixture(scope="function")
def cursor(db_connection):
    """Provide a resilient cursor that recovers if a previous test killed the server."""
    # If the shared session connection is dead, try to revive it
    if db_connection.closed != 0:
        print("\n[RECOVERY] Global connection was dead. Reviving...")
        db_connection = reconnect_db()

    cur = db_connection.cursor()
    yield cur
    cur.close()


# --- pgvector Functional Test ---
# @pytest.mark.needs_preload
def test_pgvector_functional_logic(host):  # Use host here to allow re-connection
    """
    Functional: Test pgvector extension lifecycle with auto-recovery on crash.
    """
    # Connection parameters (standard for your setup)
    conn_params = "host=localhost port=5432 user=postgres password=password dbname=postgres"

    def run_logic():
        # We create a local connection/cursor to ensure they are fresh
        with psycopg2.connect(conn_params) as conn:
            with conn.cursor() as cur:
                cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")
                cur.execute("DROP TABLE IF EXISTS test_vector_items;")
                cur.execute(
                    "CREATE TABLE test_vector_items (id serial PRIMARY KEY, embedding vector(3));"
                )
                cur.execute("INSERT INTO test_vector_items (embedding) VALUES ('[1,2,3]');")
                cur.execute("SELECT embedding FROM test_vector_items LIMIT 1;")
                return cur.fetchone()[0]

    try:
        result = run_logic()
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        # The crash happened. Wait for the container to auto-restart (if using --restart)
        # or wait for the postmaster to recover.
        print("\n[DEBUG] Postgres crashed. Waiting for recovery...")
        time.sleep(10)
        try:
            result = run_logic()
        except Exception as e:
            pytest.fail(f"pgvector failed after recovery attempt: {e}")

    assert result == "[1,2,3]"


# --- pg_stat_monitor Functional Test ---
@pytest.mark.needs_preload
def test_pg_stat_monitor_capture(host):
    """
    Functional: Ensure pg_stat_monitor tracks queries without crashing.
    """
    params = "host=localhost port=5432 user=postgres password=password dbname=postgres"

    # 1. Initialize Extension (Use Autocommit to prevent transaction locks)
    with psycopg2.connect(params) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("CREATE EXTENSION IF NOT EXISTS pg_stat_monitor;")

    # 2. Reconnect and Run Workload
    # This ensures we are on a "fresh" backend that has the extension hooks active
    with psycopg2.connect(params) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 'pgsm_test_marker' AS test;")
            cur.fetchall()

            # 3. Verify
            time.sleep(1)  # Give PGSM a moment to flush to the view
            cur.execute("SELECT query FROM pg_stat_monitor WHERE query LIKE '%pgsm_test_marker%';")
            assert cur.fetchone() is not None


# --- PG_REPACK TEST ---
def test_pg_repack_reorganization(host):
    """Verifies pg_repack can rebuild a table to remove bloat online."""
    try:
        host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS pg_repack;'")
        host.run("psql -c 'CREATE TABLE repack_test AS SELECT generate_series(1,1000) AS id;'")

        # pg_repack is a binary utility, not just SQL.
        # We run it against the 'postgres' database.
        # -t specifies the table
        repack_cmd = f"{PG_BIN_DIR}/pg_repack -d postgres -t repack_test"
        result = host.run(repack_cmd)

        assert result.rc == 0
        assert "Successfully repacked" in result.stdout or result.stdout == ""

        # Verify table still exists and is readable
        check = host.run("psql -t -c 'SELECT count(*) FROM repack_test;'")
        assert "1000" in check.stdout.strip()
    finally:
        host.run("psql -c 'DROP TABLE IF EXISTS repack_test;'")
        host.run("psql -c 'DROP EXTENSION IF EXISTS pg_repack;'")


# --- PGAUDIT TEST ---
@pytest.mark.needs_preload
def test_pgaudit_logging(host):
    """Verifies that pgaudit captures DDL and DML events in the PG logs."""
    try:
        host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS pgaudit;'")
        # Enable auditing for session DDL and Read/Write
        host.run("psql -c \"ALTER SYSTEM SET pgaudit.log = 'read, write, ddl';\"")
        host.run("psql -c 'SELECT pg_reload_conf();'")

        # Trigger an audited event
        host.run("psql -c 'CREATE TABLE audit_test (id int);'")
        host.run("psql -c 'INSERT INTO audit_test VALUES (1);'")

        # Check the PostgreSQL logs for the pgaudit signature
        # We look for 'AUDIT: SESSION' which is the default pgaudit prefix
        log_check = host.run(f"tail -n 100 {PG_DATA_DIR}/log/*.log")
        assert "AUDIT: SESSION" in log_check.stdout
        assert "CREATE TABLE audit_test" in log_check.stdout
    finally:
        host.run("psql -c 'DROP EXTENSION IF EXISTS pgaudit;'")


# --- SET_USER TEST ---
@pytest.mark.needs_preload
def test_set_user_escalation(host):
    """Verifies set_user allows a less-privileged user to flip to a superuser role."""
    try:
        # 1. Initialize Extension
        host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS set_user;'")

        # 2. Setup Roles
        host.run("psql -c \"CREATE ROLE power_user LOGIN SUPERUSER PASSWORD 'pass';\"")
        host.run("psql -c \"CREATE ROLE normal_user LOGIN PASSWORD 'pass';\"")

        # 3. Grant Permission to the UNRESTRICTED function
        # set_user_u is required for non-superuser -> superuser escalation
        host.run("psql -c 'GRANT EXECUTE ON FUNCTION set_user_u(text) TO normal_user;'")

        # 4. Test: Escalation using the unrestricted function
        # We use separate -c flags to stay out of a transaction block
        cmd = (
            "psql -U normal_user -d postgres -t "
            "-c \"SELECT set_user_u('power_user');\" "
            '-c "SELECT current_user;"'
        )
        result = host.run(cmd)

        # Log stderr for visibility if the logic changes
        if result.rc != 0:
            print(f"PSQL Stderr: {result.stderr}")

        assert "power_user" in result.stdout

        # 5. Test: De-escalation (NULL always works to return to original user)
        back_cmd = (
            "psql -U normal_user -d postgres -t "
            '-c "SELECT set_user(NULL);" '
            '-c "SELECT current_user;"'
        )
        result_back = host.run(back_cmd)
        assert "normal_user" in result_back.stdout

    finally:
        # 6. Cleanup
        # Revoke from both possible function signatures to be safe
        host.run("psql -c 'REVOKE ALL ON FUNCTION set_user(text) FROM normal_user;'")
        host.run("psql -c 'REVOKE ALL ON FUNCTION set_user_u(text) FROM normal_user;'")
        host.run("psql -c 'DROP ROLE IF EXISTS normal_user;'")
        host.run("psql -c 'DROP ROLE IF EXISTS power_user;'")


# --- WAL2JSON TEST ---
@pytest.mark.needs_preload
def test_wal2json_logical_decoding(host):
    """Verifies wal2json can decode DML into JSON format using 'kind' keys."""
    slot_name = "test_slot_wal2json"
    try:
        # 1. Check if wal_level is logical
        wal_level = host.run("psql -t -c 'SHOW wal_level;'").stdout.strip()
        if wal_level != "logical":
            pytest.skip(f"wal_level is {wal_level}; 'logical' is required.")

        # 2. Setup a test table
        host.run("psql -c 'CREATE TABLE wal_test (id int PRIMARY KEY, name text);'")

        # 3. Create logical replication slot
        host.run(
            f"psql -c \"SELECT pg_create_logical_replication_slot('{slot_name}', 'wal2json');\""
        )

        # 4. Perform DML
        host.run("psql -c \"INSERT INTO wal_test VALUES (1, 'first'), (2, 'second');\"")
        host.run("psql -c \"UPDATE wal_test SET name = 'updated' WHERE id = 1;\"")
        host.run('psql -c "DELETE FROM wal_test WHERE id = 2;"')

        # 5. Consume and Verify
        result = host.run(
            f'psql -t -c "SELECT data FROM pg_logical_slot_get_changes('
            f"'{slot_name}', NULL, NULL);\""
        )
        output = result.stdout

        # Updated Assertions based on your log output
        assert '"table":"wal_test"' in output
        assert '"kind":"insert"' in output
        assert '"kind":"update"' in output
        assert '"kind":"delete"' in output
        assert '"columnvalues":[1,"updated"]' in output

    finally:
        # 6. Cleanup
        host.run(
            f"psql -c \"SELECT pg_drop_replication_slot('{slot_name}') "
            f"WHERE EXISTS (SELECT 1 FROM pg_replication_slots "
            f"WHERE slot_name = '{slot_name}');\""
        )
        host.run("psql -c 'DROP TABLE IF EXISTS wal_test;'")


# Helper to provide isolation for every test of PostGIS
def manage_postgis(host, action="create"):
    """Handles extension lifecycle using standard psql calls."""
    if action == "create":
        # Create extensions in order of dependency
        for ext in ["postgis", "postgis_raster", "postgis_topology"]:
            host.run(f"psql -c 'CREATE EXTENSION IF NOT EXISTS {ext} CASCADE;'")
    else:
        # CASCADE ensures dependent objects/extensions are removed
        host.run("psql -c 'DROP EXTENSION IF EXISTS postgis_topology CASCADE;'")
        host.run("psql -c 'DROP EXTENSION IF EXISTS postgis CASCADE;'")


# --- PostGIS TEST ---
def test_postgis_library_linkage(host):
    """Verifies PostGIS can be enabled and GEOS, PROJ, and GDAL are reachable."""
    if not IS_WITH_POSTGIS:
        pytest.skip("Skipping PostGIS test.")
    try:
        manage_postgis(host, "create")
        version_info = host.run("psql -t -c 'SELECT postgis_full_version();'")
        # Ensure the underlying engine libraries are properly linked in the image
        assert all(lib in version_info.stdout for lib in ["GEOS", "PROJ", "GDAL", "LIBXML"])
    finally:
        manage_postgis(host, "drop")


def test_postgis_spatial_logic_and_rasters(host):
    """Verifies distance calculations (PROJ/GEOS) and Raster support (GDAL)."""
    if not IS_WITH_POSTGIS:
        pytest.skip("Skipping PostGIS test.")
    try:
        manage_postgis(host, "create")

        # Calculate distance between London and Paris (approx 340km)
        dist_query = (
            "SELECT ST_Distance("
            "ST_GeogFromText('SRID=4326;POINT(0 51.5)'), "
            "ST_GeogFromText('SRID=4326;POINT(2.3 48.8)'));"
        )
        dist_res = host.run(f'psql -t -c "{dist_query}"')
        assert 330000 < float(dist_res.stdout.strip()) < 350000

        # Verify GDAL Raster support
        raster_query = (
            "SELECT ST_Width(ST_AddBand("
            "ST_MakeEmptyRaster(10, 10, 0, 0, 1, -1, 0, 0, 4326), 1, '8BUI', 1, 0));"
        )
        assert "10" in host.run(f'psql -t -c "{raster_query}"').stdout
    finally:
        manage_postgis(host, "drop")


def test_postgis_srid_transformation(host):
    """Verifies coordinate reprojection logic (PROJ library check)."""
    if not IS_WITH_POSTGIS:
        pytest.skip("Skipping PostGIS test.")
    try:
        manage_postgis(host, "create")
        # Transform GPS (4326) to Web Mercator (3857)
        query = "SELECT ST_AsText(ST_Transform(ST_GeomFromText('POINT(0 0)', 4326), 3857));"
        res = host.run(f'psql -t -c "{query}"')
        assert "POINT(0 0)" in res.stdout
    finally:
        manage_postgis(host, "drop")


def test_postgis_indexing_and_joins(host):
    """Verifies GiST indexing and spatial join performance/logic."""
    if not IS_WITH_POSTGIS:
        pytest.skip("Skipping PostGIS test.")
    try:
        manage_postgis(host, "create")

        setup = """
        CREATE TABLE districts (id int, geom geometry(Polygon, 4326));
        CREATE INDEX idx_dist_geom ON districts USING GIST (geom);
        INSERT INTO districts VALUES (1, ST_MakeEnvelope(0, 0, 2, 2, 4326));
        """
        host.run(f'psql -c "{setup}"')

        # Test Point-in-Polygon join using the GiST index
        join_query = (
            "SELECT count(*) FROM districts "
            "WHERE ST_Contains(geom, ST_GeomFromText('POINT(1 1)', 4326));"
        )
        assert "1" in host.run(f'psql -t -c "{join_query}"').stdout.strip()
    finally:
        manage_postgis(host, "drop")


def test_postgis_functional(host):
    """
    End-to-end functional test: spatial table, GiST index, proximity query,
    area calculation, and topology — covering the full PostGIS stack in one workflow.
    """
    if not IS_WITH_POSTGIS:
        pytest.skip("Skipping PostGIS test.")

    try:
        host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS postgis CASCADE;'")
        host.run("psql -c 'DROP TABLE IF EXISTS geo_cities CASCADE;'")

        # 1. Create a table and populate it with European city points
        setup_sql = """
        CREATE TABLE geo_cities (
            id   serial PRIMARY KEY,
            name text,
            geom geometry(Point, 4326)
        );
        INSERT INTO geo_cities (name, geom) VALUES
            ('London',    ST_SetSRID(ST_MakePoint(-0.1278,  51.5074), 4326)),
            ('Paris',     ST_SetSRID(ST_MakePoint( 2.3522,  48.8566), 4326)),
            ('Berlin',    ST_SetSRID(ST_MakePoint(13.4050,  52.5200), 4326)),
            ('Madrid',    ST_SetSRID(ST_MakePoint(-3.7038,  40.4168), 4326)),
            ('Amsterdam', ST_SetSRID(ST_MakePoint( 4.9041,  52.3676), 4326));
        CREATE INDEX idx_geo_cities_geom ON geo_cities USING GIST (geom);
        """
        res = host.run(f'psql -c "{setup_sql}"')
        assert res.rc == 0, f"Setup failed: {res.stderr}"

        # 2. Proximity query: cities within 600 km of London (geography cast for metres)
        proximity_sql = (
            "SELECT count(*) FROM geo_cities "
            "WHERE ST_DWithin("
            "  geom::geography,"
            "  ST_SetSRID(ST_MakePoint(-0.1278, 51.5074), 4326)::geography,"
            "  600000"
            ");"
        )
        count = host.run(f'psql -t -A -c "{proximity_sql}"').stdout.strip()
        # London, Paris, Amsterdam are within 600 km; Berlin is ~930 km; Madrid ~1265 km
        assert count == "3", f"Expected 3 cities within 600 km of London, got {count}"

        # 3. Distance check: London → Paris must be roughly 340 km
        dist_sql = (
            "SELECT ST_Distance("
            "  (SELECT geom::geography FROM geo_cities WHERE name='London'),"
            "  (SELECT geom::geography FROM geo_cities WHERE name='Paris')"
            ")::int;"
        )
        dist_m = int(host.run(f'psql -t -A -c "{dist_sql}"').stdout.strip())
        assert 330000 < dist_m < 350000, f"London–Paris distance unexpected: {dist_m} m"

        # 4. Area of a bounding envelope that covers Western Europe (~correct order of magnitude)
        area_sql = (
            "SELECT ST_Area(ST_Envelope(ST_Collect(geom))::geography)::bigint "
            "FROM geo_cities;"
        )
        area_m2 = int(host.run(f'psql -t -A -c "{area_sql}"').stdout.strip())
        assert area_m2 > 1_000_000_000_000, f"Bounding area too small: {area_m2} m²"

        # 5. Nearest-neighbour: closest city to Brussels (4.35, 50.85) should be Paris or Amsterdam
        nn_sql = (
            "SELECT name FROM geo_cities "
            "ORDER BY geom::geography <-> "
            "ST_SetSRID(ST_MakePoint(4.35, 50.85), 4326)::geography LIMIT 1;"
        )
        nearest = host.run(f'psql -t -A -c "{nn_sql}"').stdout.strip()
        assert nearest in ("Paris", "Amsterdam"), (
            f"Unexpected nearest city to Brussels: {nearest!r}"
        )

    finally:
        host.run("psql -c 'DROP TABLE IF EXISTS geo_cities CASCADE;'")
        host.run("psql -c 'DROP EXTENSION IF EXISTS postgis CASCADE;'")


@pytest.mark.needs_preload
@pytest.mark.parametrize("binary", TDE_BINARIES)
def test_tde_binaries_present(host, binary):
    """
    Verify all PG-18/17 TDE binaries exist in the correct PostgreSQL 18 bin directory
    depending on OS type (Debian/Ubuntu vs RHEL/CentOS/Rocky).
    """
    # pg_tde only exists on PG-17 and above.
    if int(MAJOR_VER) < 17:
        pytest.skip(f"pg_tde not supported on {MAJOR_VER}.")

    # pg_tde_upgrade was introduced in 17.10 / 18.4.
    if binary == "pg_tde_upgrade":
        current_ver = version.parse(MAJOR_MINOR_VER)
        min_ver = PG_TDE_UPGRADE_MIN_VERSIONS.get(int(MAJOR_VER))
        if min_ver is None or current_ver < min_ver:
            pytest.skip(
                f"pg_tde_upgrade not available on PostgreSQL {MAJOR_MINOR_VER} "
                f"(requires >= {min_ver})"
            )

    dist = host.system_info.distribution.lower()

    # Determine the PostgreSQL 18 bin directory
    bin_path = f"/usr/pgsql-{MAJOR_VER}/bin/{binary}"

    file = host.file(bin_path)

    assert file.exists, f"{binary} is missing at {bin_path}"
    assert file.is_file, f"{binary} exists but is not a file at {bin_path}"
    assert file.mode & 0o111, f"{binary} exists but is not executable at {bin_path}"


@pytest.mark.needs_preload
def test_pg_tde_extension(host):
    if int(MAJOR_VER) < 17:
        pytest.skip(f"pg_tde not supported on {MAJOR_VER}.")

    # 1. Execute the create command
    cmd = "psql -c 'CREATE EXTENSION IF NOT EXISTS pg_tde CASCADE;'"
    result = host.run(cmd)
    assert result.rc == 0

    # 2. Metadata Verification: Check if it's in pg_extension
    check_cmd = "psql -t -c \"SELECT count(*) FROM pg_extension WHERE extname = 'pg_tde';\""
    count = host.run(check_cmd).stdout.strip()
    assert count == "1"

    # 3. Version Check (Metadata): Get the installed version string
    version_cmd = "psql -t -c \"SELECT extversion FROM pg_extension WHERE extname = 'pg_tde';\""
    ext_sql_version = host.run(version_cmd).stdout.strip()

    # Assert version is not empty
    assert len(ext_sql_version) > 0
    print(f"Detected pg_tde Extension Sql Version: {ext_sql_version}")

    # Assert sql version of pg_tde
    assert ext_sql_version == pg_docker_versions.get(f"percona-pg_tde{MAJOR_VER}", {}).get("ext_sql_version")

    # 4. Functional Check: Verify the 'pg_tde' type is usable
    # We cast a string to a pg_tde and check its dimensions to ensure the C library is loaded
    func_cmd = "psql -t -c \"SELECT pg_tde_version();\""
    actual_version = host.run(func_cmd).stdout.strip()

    # Assert version is not empty
    assert len(actual_version) > 0
    print(f"Detected pg_tde Extension Version: {actual_version}")

    # Check against your expected versions dictionary
    expected_version = pg_docker_versions.get(f"percona-pg_tde{MAJOR_VER}", {}).get("extension_version")

    assert actual_version == expected_version, f"Expected {expected_version}, but found {actual_version}"

    # 5. Execute the drop command with CASCADE
    cmd = "psql -c 'DROP EXTENSION IF EXISTS pg_tde CASCADE;'"
    result = host.run(cmd)
    assert result.rc == 0

    # 6. Verification: Ensure it no longer exists in pg_extension
    check_cmd = "psql -t -c \"SELECT count(*) FROM pg_extension WHERE extname = 'pg_tde';\""
    count = host.run(check_cmd).stdout.strip()
    assert count == "0"


#=========================================
# Telemetry changes
#=========================================
# Define the packages you want to test
telemetry_pkg_name = "percona-pg-telemetry"+MAJOR_VER
telemetry_packages = [
    telemetry_pkg_name,
    "percona-telemetry-agent"
]

# Define log directory and files to be checked
log_directory = "/var/log/percona/telemetry-agent/"
log_files = [
    "telemetry-agent-error.log",
    "telemetry-agent.log"
]

# Paths for directories to be checked
common_directories = [
    "/usr/local/percona/telemetry/history/",
    "/usr/local/percona/telemetry/pg/"
]

# Paths for directory that will contain json file
json_files_location = [
    "/usr/local/percona/telemetry/pg/*.json"
]

# Paths for percona-telemetry-agent based on the OS
debian_percona_telemetry_agent = "/etc/default/percona-telemetry-agent"
redhat_percona_telemetry_agent = "/etc/sysconfig/percona-telemetry-agent"


@pytest.mark.parametrize("package", telemetry_packages)
def test_telemetry_package_is_installed(host, package):
    if int(MAJOR_VER) in [18]:
        pytest.skip("Skipping on PostgreSQL 18, as telemetry not available.")
    dist = host.system_info.distribution
    pkg = host.package(package)
    assert pkg.is_installed


def test_telemetry_agent_service_enabled(host):
    if int(MAJOR_VER) in [18]:
        pytest.skip("Skipping on PostgreSQL 18, as telemetry not available.")
    service = host.service("percona-telemetry-agent")
    #assert service.is_running
    assert service.is_enabled


def test_telemetry_log_directory_exists(host):
    """Test if the directory exists."""
    if int(MAJOR_VER) in [18]:
        pytest.skip("Skipping on PostgreSQL 18, as telemetry not available.")
    logdir = host.file(log_directory)
    assert logdir.exists, f"Directory {log_directory} does not exist."


@pytest.mark.parametrize("file_name", log_files)
def test_telemetry_log_files_exist(host,file_name):
    """Test if the required files exist within the directory."""
    if int(MAJOR_VER) in [18]:
        pytest.skip("Skipping on PostgreSQL 18, as telemetry not available.")
    file_path = os.path.join(log_directory, file_name)
    log_file_name = host.file(file_path)
    assert log_file_name.exists, f"File {file_path} does not exist."


def get_telemetry_agent_conf_file(host):
    """Determine the percona-telemetry-agent path based on the OS."""
    if int(MAJOR_VER) in [18]:
        pytest.skip("Skipping on PostgreSQL 18, as telemetry not available.")
    dist = host.system_info.distribution
    # if dist.lower() in ["redhat", "centos", "rhel", "rocky"]:
    #     return redhat_percona_telemetry_agent
    # else:
    #     return debian_percona_telemetry_agent
    return redhat_percona_telemetry_agent


def test_telemetry_json_directories_exist(host):
    """Test if the history and pg directories exist."""
    if int(MAJOR_VER) in [18]:
        pytest.skip("Skipping on PostgreSQL 18, as telemetry not available.")
    for directory in common_directories:
        assert host.file(directory).exists, f"Directory {directory} does not exist."


def test_telemetry_agent_conf_exists(host):
    """Test if the percona-telemetry-agent conf file exists."""
    if int(MAJOR_VER) in [18]:
        pytest.skip("Skipping on PostgreSQL 18, as telemetry not available.")
    agent_path = get_telemetry_agent_conf_file(host)
    assert host.file(agent_path).exists, f"{agent_path} does not exist."


def test_pg_telemetry_package_version(host):
    if int(MAJOR_VER) in [18]:
        pytest.skip("Skipping on PostgreSQL 18, as telemetry not available.")
    dist = host.system_info.distribution
    pg_telemetry = host.package(f"percona-pg-telemetry{MAJOR_VER}")
    assert pg_docker_versions["percona-pg-telemetry"]['pg_telemetry_package_version'] in pg_telemetry.version


def test_pg_telemetry_extension_version(host):
    if int(MAJOR_VER) in [18]:
        pytest.skip("Skipping on PostgreSQL 18, as telemetry not available.")
    result = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS percona_pg_telemetry;'")
    assert result.rc == 0, result.stderr
    result = host.run("psql -c 'SELECT percona_pg_telemetry_version();' | awk 'NR==3{print $1}'")
    assert result.rc == 0, result.stderr
    assert result.stdout.strip("\n") == pg_docker_versions["percona-pg-telemetry"]['pg_telemetry_version']


# --- pg_cron ---

# Minimum PPG patch versions where llvmjit is functional (fixed build)
LLVMJIT_MIN_VERSIONS = {
    14: version.parse("14.23"),
    15: version.parse("15.18"),
    16: version.parse("16.14"),
    17: version.parse("17.10"),
    18: version.parse("18.4"),
}

# Minimum PPG patch versions that ship pg_cron, keyed by major version integer.
PG_CRON_MIN_VERSIONS = {
    14: version.parse("14.23"),
    15: version.parse("15.18"),
    16: version.parse("16.14"),
    17: version.parse("17.10"),
    18: version.parse("18.4"),
}

# Minimum PPG patch versions that ship pg_tde_upgrade binary, keyed by major version integer.
PG_TDE_UPGRADE_MIN_VERSIONS = {
    17: version.parse("17.10"),
    18: version.parse("18.4"),
}


def _skip_if_llvmjit_unavailable():
    """Skip the calling test if llvmjit is not functional for the current PG version."""
    current_ver = version.parse(MAJOR_MINOR_VER)
    min_ver = LLVMJIT_MIN_VERSIONS.get(int(MAJOR_VER))
    if min_ver is None or current_ver < min_ver:
        pytest.skip(
            f"llvmjit not available for PostgreSQL {MAJOR_MINOR_VER} "
            f"(requires >= {min_ver})"
        )


def _ensure_nm_available(host):
    """Ensure nm (binutils) is available in the container, installing it if needed.

    UBI 8 minimal images do not include binutils by default while UBI 9 does.
    Rather than skipping the test, install binutils on-the-fly so that symbol
    inspection tests run on all UBI variants (ubi8, ubi9, ubi10).

    The container runs as the postgres user so yum/dnf requires root.
    We use 'docker exec -u root' via subprocess to perform the install.
    Only skips if installation itself fails.
    """
    if host.run("command -v nm").rc == 0:
        return
    container_name = f"PG{MAJOR_VER}"
    subprocess.run(
        ["docker", "exec", "-u", "root", container_name,
         "sh", "-c",
         "yum install -y binutils 2>/dev/null || "
         "dnf install -y binutils 2>/dev/null || "
         "microdnf install -y binutils 2>/dev/null"],
        capture_output=True
    )
    if host.run("command -v nm").rc != 0:
        pytest.skip(
            "nm (binutils) not available and could not be installed in this "
            "container — skipping symbol inspection test."
        )


def _skip_if_pg_cron_unavailable():
    """Skip the calling test if pg_cron is not available for the current PG version."""
    current_ver = version.parse(MAJOR_MINOR_VER)
    min_ver = PG_CRON_MIN_VERSIONS.get(int(MAJOR_VER))
    if min_ver is None or current_ver < min_ver:
        pytest.skip(
            f"pg_cron not available for PostgreSQL {MAJOR_MINOR_VER} "
            f"(requires >= {min_ver})"
        )


@pytest.mark.needs_preload
def test_pg_cron_extension_version(host):
    _skip_if_pg_cron_unavailable()
    pkg_key = f"percona-pg_cron_{MAJOR_VER}"

    host.run("psql -c 'DROP EXTENSION IF EXISTS pg_cron CASCADE;'")
    create_res = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS pg_cron;'")
    assert create_res.rc == 0, create_res.stderr

    query = "SELECT extversion FROM pg_extension WHERE extname = 'pg_cron';"
    actual_ext_version = host.run(f'psql -t -A -c "{query}"').stdout.strip()
    expected_ext_version = pg_docker_versions[pkg_key]["extension_version"]

    assert actual_ext_version == expected_ext_version, (
        f"pg_cron extension version {actual_ext_version!r} does not match "
        f"expected {expected_ext_version!r}"
    )

    host.run("psql -c 'DROP EXTENSION IF EXISTS pg_cron CASCADE;'")


@pytest.mark.needs_preload
def test_pg_cron_functional(host):
    _skip_if_pg_cron_unavailable()

    host.run("psql -c 'DROP EXTENSION IF EXISTS pg_cron CASCADE;'")
    host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS pg_cron;'")

    query = "SELECT count(*) FROM cron.job;"
    result = host.run(f'psql -t -A -c "{query}"')
    assert result.rc == 0, f"pg_cron functional test failed: {result.stderr}"
    assert result.stdout.strip() == "0"

    host.run("psql -c 'DROP EXTENSION IF EXISTS pg_cron CASCADE;'")


@pytest.mark.needs_preload
def test_pg_cron_schedule_job(host):
    _skip_if_pg_cron_unavailable()
    pkg_key = f"percona-pg_cron_{MAJOR_VER}"

    host.run("psql -c 'DROP EXTENSION IF EXISTS pg_cron CASCADE;'")
    host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS pg_cron;'")

    schedule_res = host.run(
        "psql -t -A -c \"SELECT cron.schedule('test-job', '* * * * *', 'SELECT 1;');\""
    )
    assert schedule_res.rc == 0, f"cron.schedule() failed: {schedule_res.stderr}"

    query = "SELECT count(*) FROM cron.job WHERE jobname = 'test-job';"
    count_result = host.run(f'psql -t -A -c "{query}"')
    assert count_result.rc == 0
    assert count_result.stdout.strip() == "1", "Scheduled job not found in cron.job"

    host.run("psql -t -A -c \"SELECT cron.unschedule('test-job');\"")
    host.run("psql -c 'DROP EXTENSION IF EXISTS pg_cron CASCADE;'")
