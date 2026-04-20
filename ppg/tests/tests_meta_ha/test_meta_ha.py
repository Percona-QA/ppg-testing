import os
import pytest

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


@pytest.mark.upgrade
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


@pytest.mark.upgrade
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
