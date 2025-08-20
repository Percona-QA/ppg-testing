import os
import pytest

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')

RPM_PACKAGES = ['percona-patroni', 'etcd', 'percona-haproxy', 'python3-etcd', 'python3.12-etcd']
DEB_PACKAGES = ['percona-patroni', 'etcd', 'percona-haproxy', 'etcd-client', 'etcd-server']


@pytest.mark.upgrade
@pytest.mark.parametrize("package", DEB_PACKAGES)
def test_deb_package_is_installed(host, package):
    ds = host.system_info.distribution
    if ds.lower() in ["redhat", "centos", "rhel", "rocky", "ol"]:
        pytest.skip("This test only for Debian based platforms")
    if package == 'etcd' and host.system_info.distribution == "debian" and host.system_info.release == '12':
        pytest.skip("This test not for Debian 12")
    pkg = host.package(package)
    assert pkg.is_installed

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
