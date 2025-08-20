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

and host.system_info.release.startswith("9"):

@pytest.mark.upgrade
@pytest.mark.parametrize("package", RPM_PACKAGES)
def test_rpm_package_is_installed(host, package):
    with host.sudo():
        ds = host.system_info.distribution
        if ds in ["debian", "ubuntu"]:
            pytest.skip("This test only for RHEL based platforms")
        if package == 'python3-etcd' and host.system_info.release.startswith("10"):
            pytest.skip("This test only for RHEL based version 8 & 9")
        if (package == 'python3.12-etcd') and \
        (host.system_info.release.startswith("8") or host.system_info.release.startswith("9")):
            pytest.skip("This test only for RHEL based version 10")
        pkg = host.package(package)
        assert pkg.is_installed
