# PSP 16 ships the same libpq/libecpg packaging as ppg-16.x — reuse the ppg
# component tests verbatim. pytest collects the imported test_* functions.
from ..tests_ppg.test_components import *  # noqa: F401,F403
