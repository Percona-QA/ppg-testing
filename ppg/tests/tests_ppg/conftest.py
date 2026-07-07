import os
import re

import pytest
from packaging import version

UBUNTU26_MIN_VERSIONS = {
    14: version.parse("14.23"),
    15: version.parse("15.18"),
    16: version.parse("16.14"),
    17: version.parse("17.10"),
    18: version.parse("18.4"),
}


def _ubuntu26_skip_reason():
    """Return a skip reason string if this host+version combination is not
    supported on Ubuntu 26, or *None* if the test should proceed.

    Logic
    -----
    Ubuntu 26 support was introduced from 14.23 / 15.18 / 16.14 / 17.10 / 18.4.
    When VERSION (the target being installed/tested) is below the minimum for its
    major series the test must be skipped because the Ansible tasks already issued
    a ``meta: end_host`` and the package was never installed.
    """
    ver_str = re.sub(r"^(ppg|psp)-", "", os.getenv("VERSION", ""))
    if not ver_str:
        return None

    try:
        parsed = version.parse(ver_str)
        major = int(str(parsed).split(".")[0])
    except Exception:
        return None

    min_ver = UBUNTU26_MIN_VERSIONS.get(major)
    if min_ver and parsed < min_ver:
        return f"Ubuntu 26 with PG {ver_str} < {min_ver} is not supported — installation was skipped"
    return None


@pytest.fixture(autouse=True)
def skip_unsupported_ubuntu26(host):
    """Auto-use fixture: skip every test in this package when running on
    Ubuntu 26 with a PG version that pre-dates Ubuntu 26 support."""
    dist = host.system_info.distribution.lower()
    if dist != "ubuntu":
        return

    if not host.system_info.release.startswith("26"):
        return

    reason = _ubuntu26_skip_reason()
    if reason:
        pytest.skip(reason)
