# PSP 16 ships the same tools/extensions stack as ppg-16.x (patroni, pgbackrest,
# pgpool, postgis, pg_stat_monitor, ...) — reuse the ppg tool tests verbatim.
# The pg_tde tests inside are gated on MAJOR_VER >= 17 and therefore skip here;
# tests_psp/test_tde.py provides the ungated PSP equivalents.
from ..tests_ppg.test_tools import *  # noqa: F401,F403
