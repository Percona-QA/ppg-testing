"""Shared helpers for the tests_ppg suite: distro families, per-distro paths and
version gates."""
from packaging import version

# testinfra's host.system_info.distribution values, lowercased.
RPM_DISTS = ["redhat", "centos", "rhel", "rocky", "ol"]
DEB_DISTS = ["debian", "ubuntu"]

# First minor release of each major that carries the Q2-2026 packaging changes
# (llvmjit fix, pg_cron, libpgpoolpcp3, Ubuntu 26 support, pg_tde_upgrade).
BASELINE_2026Q2 = {
    14: version.parse("14.23"),
    15: version.parse("15.18"),
    16: version.parse("16.14"),
    17: version.parse("17.10"),
    18: version.parse("18.4"),
}


def is_rpm(dist):
    return dist.lower() in RPM_DISTS


def is_deb(dist):
    return dist.lower() in DEB_DISTS


def pg_bin_dir(dist, major):
    """Directory holding the PostgreSQL server/client binaries."""
    if is_rpm(dist):
        return f"/usr/pgsql-{major}/bin"
    return f"/usr/lib/postgresql/{major}/bin"


def pg_lib_dir(dist, major):
    """Directory holding the PostgreSQL shared libraries (llvmjit.so, pgxs, ...)."""
    if is_rpm(dist):
        return f"/usr/pgsql-{major}/lib"
    return f"/usr/lib/postgresql/{major}/lib"


def meets_min_version(table, ver_str):
    """True if ver_str is at or above the minimum its major has in `table`
    (a {major: Version} map). Majors absent from the table never meet it."""
    current = version.parse(ver_str)
    minimum = table.get(current.major)
    return minimum is not None and current >= minimum
