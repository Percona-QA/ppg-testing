import pytest

from tools import gen_groups


@pytest.fixture(scope="session", autouse=True)
def materialized_groups():
    gen_groups.ensure()
