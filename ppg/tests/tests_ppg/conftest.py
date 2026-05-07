import os
import pytest
from packaging import version


@pytest.fixture(autouse=True)
def skip_unsupported_ubuntu(host):
    dist = host.system_info.distribution.lower()
    if dist != "ubuntu":
        return

    ver_str = os.getenv("VERSION", "").replace("ppg-", "")
    if ver_str and version.parse(ver_str) < version.parse("18.4"):
        pytest.skip(f"Ubuntu with PG {ver_str} < 18.4 is not supported")
