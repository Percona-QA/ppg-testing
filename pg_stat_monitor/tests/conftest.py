import os

import pytest
from packaging import version


UBUNTU26_MIN_VERSIONS = {
    14: version.parse("14.23"),
    15: version.parse("15.18"),
    16: version.parse("16.14"),
    17: version.parse("17.10"),
    18: version.parse("18.4"),
}


@pytest.fixture(autouse=True)
def skip_unsupported_ubuntu(host):
    dist = host.system_info.distribution.lower()
    if dist != "ubuntu":
        return

    if not host.system_info.release.startswith("26"):
        return

    ver_str = os.getenv("VERSION", "").replace("ppg-", "")
    if not ver_str:
        return

    try:
        parsed = version.parse(ver_str)
        major = int(str(parsed).split(".")[0])
    except Exception:
        return

    min_ver = UBUNTU26_MIN_VERSIONS.get(major)
    if min_ver and parsed < min_ver:
        pytest.skip(f"Ubuntu 26 with PG {ver_str} < {min_ver} is not supported")
