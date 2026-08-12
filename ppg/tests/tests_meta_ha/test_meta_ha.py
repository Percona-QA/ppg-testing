import os
import re

import pytest
from packaging import version

import testinfra.utils.ansible_runner

from .. import settings

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')

RPM_PACKAGES = ['percona-patroni', 'etcd', 'percona-haproxy', 'python3-etcd', 'python3.12-etcd']
DEB_PACKAGES = ['percona-patroni', 'etcd', 'percona-haproxy', 'etcd-client', 'etcd-server']

pg_versions = settings.get_settings(os.environ['MOLECULE_SCENARIO_NAME'])[os.getenv("VERSION")]

# Expected versions for packages that are tracked in the version files.
# python3-etcd, python3.12-etcd, etcd-client, and etcd-server are not tracked
# individually so they are printed but not version-asserted.
EXPECTED_VERSIONS = {
    "percona-patroni": pg_versions["patroni"]["version"],
    "etcd":            pg_versions["etcd"]["version"],
    "percona-haproxy": pg_versions["haproxy"]["version"],
}

# Minimum PostgreSQL versions where percona-patroni requires python3.12+ on RHEL
# (the first version strictly after 14.23, 15.18, 16.14, 17.10, 18.4)
PATRONI_PYTHON312_MIN_VERSIONS = {
    14: version.parse("14.24"),
    15: version.parse("15.19"),
    16: version.parse("16.15"),
    17: version.parse("17.11"),
    18: version.parse("18.5"),
}


@pytest.mark.parametrize("package", DEB_PACKAGES)
def test_deb_package_is_installed(host, package):
    ds = host.system_info.distribution
    if ds.lower() in ["redhat", "centos", "rhel", "rocky", "ol"]:
        pytest.skip("This test only for Debian based platforms")
    #if package == 'etcd' and host.system_info.distribution == "debian" and host.system_info.release == '12':
    #    pytest.skip("This test not for Debian 12")
    pkg = host.package(package)
    assert pkg.is_installed
    expected = EXPECTED_VERSIONS.get(package)
    print(f"\n[VERIFYING] Package: {package}")
    print(f"            Expected: {expected or '(not tracked)'}")
    print(f"            Found:    {pkg.version}")
    if expected:
        assert expected in pkg.version, (
            f"Version mismatch for {package}. Expected: {expected}, Found: {pkg.version}"
        )
    print(f"[SUCCESS] {package} version {pkg.version} verified.")


@pytest.mark.parametrize("package", RPM_PACKAGES)
def test_rpm_package_is_installed(host, package):
    with host.sudo():
        ds = host.system_info.distribution
        if ds in ["debian", "ubuntu"]:
            pytest.skip("This test only for RHEL based platforms")
        rhel_major_version = host.system_info.release.split(".")[0]
        if package == "python3.12-etcd" and rhel_major_version in ("8", "9"):
            pytest.skip("This test is only for RHEL-based version 10")
        if package == 'python3-etcd' and rhel_major_version in ("10"):
            pytest.skip("This test only for RHEL based version 8 & 9")
        pkg = host.package(package)
        assert pkg.is_installed
        expected = EXPECTED_VERSIONS.get(package)
        print(f"\n[VERIFYING] Package: {package}")
        print(f"            Expected: {expected or '(not tracked)'}")
        print(f"            Found:    {pkg.version}")
        if expected:
            assert expected in pkg.version, (
                f"Version mismatch for {package}. Expected: {expected}, Found: {pkg.version}"
            )
        print(f"[SUCCESS] {package} version {pkg.version} verified.")


def _skip_if_patroni_python312_unavailable():
    """Skip if the python3.12+ patroni dependency isn't expected yet for the
    current PostgreSQL version."""
    current_ver = version.parse(pg_versions.get("version", "0.0"))
    min_ver = PATRONI_PYTHON312_MIN_VERSIONS.get(current_ver.major)
    if min_ver is None or current_ver < min_ver:
        pytest.skip(f"python3.12+ patroni dependency not expected for "
                    f"PostgreSQL {pg_versions.get('version')}")


def test_patroni_requires_python312(host):
    """percona-patroni must declare a hard dependency on python3.12 or newer on
    RHEL-based platforms."""
    _skip_if_patroni_python312_unavailable()
    ds = host.system_info.distribution
    if ds.lower() in ["debian", "ubuntu"]:
        pytest.skip("python3.12+ dependency pin only applies to RHEL-based packaging")
    with host.sudo():
        result = host.run("rpm -q --requires percona-patroni")
        assert result.rc == 0, f"failed to query percona-patroni requires: {result.stderr}"
        match = re.search(r"python\(abi\)\s*=\s*(\d+)\.(\d+)", result.stdout)
        assert match, (
            f"percona-patroni on {ds} {host.system_info.release} does not declare a "
            f"python(abi) requirement. Requires:\n{result.stdout}"
        )
        abi_version = (int(match.group(1)), int(match.group(2)))
        assert abi_version >= (3, 12), (
            f"percona-patroni on {ds} {host.system_info.release} requires python(abi) "
            f"{abi_version[0]}.{abi_version[1]}, expected 3.12 or newer. "
            f"Requires:\n{result.stdout}"
        )
