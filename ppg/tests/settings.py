import os

from .versions.patroni import patroni
from .versions.pgbadger import pgbadger
from .versions.pgbouncer import pgbouncer
from .versions.pgbackrest import pgbackrest
from .versions.pgaudit import pgaudit
from .versions.pg_repack import pgrepack
from .versions.ppg import get_ppg_versions
from .versions.set_user import set_user
from .versions.wal2json import wal2json

MAJOR_VER = "12"
if "11" in os.getenv("VERSION"):
    MAJOR_VER = "11"
if "13" in os.getenv("VERSION"):
    MAJOR_VER = "13"


def get_settings(distro_type):
    ppg_versions = get_ppg_versions(distro_type)

    return {"ppg-11.12": {"version": "11.12",
                          "deb_pkg_ver": ppg_versions["ppg-11.12"]['deb_pkg_ver'],
                          "deb_packages": ppg_versions["ppg-11.12"]['deb_packages'],
                          "percona-postgresql-common": '226',
                          "percona-postgresql-client-common": "226",
                          "libpq_version": "110012",
                          "pgaudit": pgaudit['ppg-11.12'],
                          "pgbackrest": pgbackrest['ppg-11.12'],
                          "patroni": patroni['ppg-11.12'],
                          "pgrepack": pgrepack['ppg-11.12'],
                          "pgbadger": pgbadger['11.12'],
                          'pgbouncer': pgbouncer['11.12'],
                          "wal2json": wal2json['11.12'],
                          "set_user": set_user['11.12'],
                          "pgrepack_package_rpm": 'percona-pg_repack11',
                          "pgrepack_package_deb": "percona-postgresql-11-repack",
                          "libpq": "Version of libpq: 110012",
                          "deb_provides": ppg_versions["ppg-11.12"]['deb_provides'],
                          "rpm7_provides": ppg_versions["ppg-11.12"]['rpm7_provides'],
                          'rpm_provides': ppg_versions["ppg-11.12"]['rpm_provides'],
                          "rpm_packages": ppg_versions["ppg-11.12"]['rpm_packages'],
                          "rpm7_packages": ppg_versions["ppg-11.12"]['rpm7_packages'],
                          "rhel_files": ppg_versions["ppg-11.12"]['rhel_files'],
                          "deb_files": ppg_versions["ppg-11.12"]['deb_files'],
                          "extensions": ppg_versions["ppg-11.12"]['extensions'],
                          "languages": ppg_versions["ppg-11.12"]['languages'],
                          "binaries": ppg_versions["ppg-11.12"]['binaries'],
                          "pg_stat_monitor": "0.9.1"
                          },
            "ppg-11.11": {"version": "11.11",
                          "deb_pkg_ver": ppg_versions["ppg-11.11"]['deb_pkg_ver'],
                          "deb_packages": ppg_versions["ppg-11.11"]['deb_packages'],
                          "percona-postgresql-common": '225',
                          "percona-postgresql-client-common": "225",
                          "libpq_version": "110011",
                          "pgaudit": pgaudit['ppg-11.11'],
                          "pgbackrest": pgbackrest['ppg-11.11'],
                          "patroni": patroni['ppg-11.11'],
                          "pgrepack": pgrepack['ppg-11.11'],
                          "pgrepack_package_rpm": 'percona-pg_repack11',
                          "pgrepack_package_deb": "percona-postgresql-11-repack",
                          "libpq": "Version of libpq: 110011",
                          "deb_provides": ppg_versions["ppg-11.11"]['deb_provides'],
                          "rpm7_provides": ppg_versions["ppg-11.11"]['rpm7_provides'],
                          'rpm_provides': ppg_versions["ppg-11.11"]['rpm_provides'],
                          "rpm_packages": ppg_versions["ppg-11.11"]['rpm_packages'],
                          "rpm7_packages": ppg_versions["ppg-11.11"]['rpm7_packages'],
                          "rhel_files": ppg_versions["ppg-11.11"]['rhel_files'],
                          "deb_files": ppg_versions["ppg-11.11"]['deb_files'],
                          "extensions": ppg_versions["ppg-11.11"]['extensions'],
                          "languages": ppg_versions["ppg-11.11"]['languages'],
                          "binaries": ppg_versions["ppg-11.11"]['binaries'],
                          "pg_stat_monitor": "0.9.0"
                          },
            "ppg-11.10": {"version": "11.10",
                          "deb_pkg_ver": ppg_versions["ppg-11.10"]['deb_pkg_ver'],
                          "deb_packages": ppg_versions["ppg-11.10"]['deb_packages'],
                          "percona-postgresql-common": '223',
                          "percona-postgresql-client-common": "223",
                          "libpq_version": "110010",
                          "pgaudit": pgaudit['ppg-11.10'],
                          "pgbackrest": pgbackrest['ppg-11.10'],
                          "patroni": patroni['ppg-11.10'],
                          "pgrepack": pgrepack['ppg-11.10'],
                          "pgrepack_package_rpm": 'percona-pg_repack11',
                          "pgrepack_package_deb": "percona-postgresql-11-repack",
                          "libpq": "Version of libpq: 110010",
                          "deb_provides": ppg_versions["ppg-11.10"]['deb_provides'],
                          "rpm7_provides": ppg_versions["ppg-11.10"]['rpm7_provides'],
                          'rpm_provides': ppg_versions["ppg-11.10"]['rpm_provides'],
                          "rpm_packages": ppg_versions["ppg-11.10"]['rpm_packages'],
                          "rpm7_packages": ppg_versions["ppg-11.10"]['rpm7_packages'],
                          "rhel_files": ppg_versions["ppg-11.10"]['rhel_files'],
                          "deb_files": ppg_versions["ppg-11.10"]['deb_files'],
                          "extensions": ppg_versions["ppg-11.10"]['extensions'],
                          "languages": ppg_versions["ppg-11.10"]['languages'],
                          "binaries": ppg_versions["ppg-11.10"]['binaries']
                          },
            "ppg-11.9": {"version": "11.9",
                         "deb_pkg_ver": ppg_versions["ppg-11.9"]['deb_pkg_ver'],
                         "deb_packages": ppg_versions["ppg-11.9"]['deb_packages'],
                         "percona-postgresql-common": '216',
                         "percona-postgresql-client-common": "216",
                         "libpq_version": "110009",
                         "pgaudit": pgaudit['ppg-11.9'],
                         "pgbackrest": pgbackrest['ppg-11.9'],
                         "patroni": patroni['ppg-11.9'],
                         "pgrepack": pgrepack['ppg-11.9'],
                         "pgrepack_package_rpm": 'percona-pg_repack11',
                         "pgrepack_package_deb": "percona-postgresql-11-repack",
                         "libpq": "Version of libpq: 110009",
                         "deb_provides": ppg_versions["ppg-11.9"]['deb_provides'],
                         "rpm7_provides": ppg_versions["ppg-11.9"]['rpm7_provides'],
                         'rpm_provides': ppg_versions["ppg-11.9"]['rpm_provides'],
                         "rpm_packages": ppg_versions["ppg-11.9"]['rpm_packages'],
                         "rpm7_packages": ppg_versions["ppg-11.9"]['rpm7_packages'],
                         "rhel_files": ppg_versions["ppg-11.9"]['rhel_files'],
                         "deb_files": ppg_versions["ppg-11.9"]['deb_files'],
                         "extensions": ppg_versions["ppg-11.9"]['extensions'],
                         "languages": ppg_versions["ppg-11.9"]['languages'],
                         "binaries": ppg_versions["ppg-11.9"]['binaries']
                         },
            "ppg-11.8": {"version": "11.8",
                         "deb_pkg_ver": ppg_versions["ppg-11.8"]['deb_pkg_ver'],
                         "deb_packages": ppg_versions["ppg-11.8"]['deb_packages'],
                         "percona-postgresql-common": '215',
                         "percona-postgresql-client-common": "215",
                         "libpq_version": "110008",
                         "pgaudit": pgaudit['ppg-11.8'],
                         "pgbackrest": pgbackrest['ppg-11.8'],
                         "patroni": patroni['ppg-11.8'],
                         "pgrepack": pgrepack['ppg-11.8'],
                         "pgrepack_package_rpm": 'percona-pg_repack11',
                         "pgrepack_package_deb": "percona-postgresql-11-repack",
                         "libpq": "Version of libpq: 110008",
                         "deb_provides": ppg_versions["ppg-11.8"]['deb_provides'],
                         "rpm7_provides": ppg_versions["ppg-11.8"]['rpm7_provides'],
                         'rpm_provides': ppg_versions["ppg-11.8"]['rpm_provides'],
                         "rpm_packages": ppg_versions["ppg-11.8"]['rpm_packages'],
                         "rpm7_packages": ppg_versions["ppg-11.8"]['rpm7_packages'],
                         "rhel_files": ppg_versions["ppg-11.8"]['rhel_files'],
                         "deb_files": ppg_versions["ppg-11.8"]['deb_files'],
                         "extensions": ppg_versions["ppg-11.8"]['extensions'],
                         "languages": ppg_versions["ppg-11.8"]['languages'],
                         "binaries": ppg_versions["ppg-11.8"]['binaries']
                         },
            "ppg-11.7": {"version": "11.7",
                         "deb_pkg_ver": ppg_versions["ppg-11.7"]['deb_pkg_ver'],
                         "deb_packages": ppg_versions["ppg-11.7"]['deb_packages'],
                         "percona-postgresql-common": '214',
                         "percona-postgresql-client-common": "214",
                         "libpq_version": "110007",
                         "pgaudit": pgaudit['ppg-11.7'],
                         "pgbackrest": pgbackrest['ppg-11.7'],
                         "patroni": patroni['ppg-11.7'],
                         "pgrepack": pgrepack['ppg-11.7'],
                         "libpq": "Version of libpq: 110007",
                         "deb_provides": ppg_versions["ppg-11.7"]['deb_provides'],
                         "rpm7_provides": ppg_versions["ppg-11.7"]['rpm7_provides'],
                         'rpm_provides': ppg_versions["ppg-11.7"]['rpm_provides'],
                         "rpm_packages": ppg_versions["ppg-11.7"]['rpm_packages'],
                         "rpm7_packages": ppg_versions["ppg-11.7"]['rpm7_packages'],
                         "rhel_files": ppg_versions["ppg-11.7"]['rhel_files'],
                         "deb_files": ppg_versions["ppg-11.7"]['deb_files'],
                         "extensions": ppg_versions["ppg-11.7"]['extensions'],
                         "languages": ppg_versions["ppg-11.7"]['languages'],
                         "binaries": ppg_versions["ppg-11.7"]['binaries']
                         },
            "ppg-11.6": {"version": "11.6",
                         "deb_pkg_ver": ppg_versions["ppg-11.6"]['deb_pkg_ver'],
                         "deb_packages": ppg_versions["ppg-11.6"]['deb_packages'],
                         "percona-postgresql-common": '210',
                         "percona-postgresql-client-common": "210",
                         "libpq_version": "110006",
                         "pgaudit": pgaudit['ppg-11.6'],
                         "pgbackrest": pgbackrest['ppg-11.6'],
                         "patroni": patroni['ppg-11.6'],
                         "pgrepack": pgrepack['ppg-11.6'],
                         "libpq": "Version of libpq: 110006",
                         "deb_provides": ppg_versions["ppg-11.6"]['deb_provides'],
                         "rpm7_provides": ppg_versions["ppg-11.6"]['rpm7_provides'],
                         'rpm_provides': ppg_versions["ppg-11.6"]['rpm_provides'],
                         "rpm_packages": ppg_versions["ppg-11.6"]['rpm_packages'],
                         "rpm7_packages": ppg_versions["ppg-11.6"]['rpm7_packages'],
                         "rhel_files": ppg_versions["ppg-11.6"]['rhel_files'],
                         "deb_files": ppg_versions["ppg-11.6"]['deb_files'],
                         "extensions": ppg_versions["ppg-11.6"]['extensions'],
                         "languages": ppg_versions["ppg-11.6"]['languages'],
                         "binaries": ppg_versions["ppg-11.6"]['binaries']
                         },
            "ppg-11.5": {"version": "11.5",
                         "deb_pkg_ver": ppg_versions["ppg-11.5"]['deb_pkg_ver'],
                         "deb_packages": ppg_versions["ppg-11.5"]['deb_packages'],
                         "percona-postgresql-common": '204',
                         "percona-postgresql-client-common": "204",
                         "libpq_version": "110005",
                         "deb_provides": ppg_versions["ppg-11.5"]['deb_provides'],
                         "rpm7_provides": ppg_versions["ppg-11.5"]['rpm7_provides'],
                         'rpm_provides': ppg_versions["ppg-11.5"]['rpm_provides'],
                         "pgaudit": pgaudit['ppg-11.5'],
                         "pgbackrest": pgbackrest['ppg-11.5'],
                         "patroni": patroni['ppg-11.5'],
                         "pgrepack": pgrepack['ppg-11.5'],
                         "libpq": "Version of libpq: 110005",
                         "binaries": ppg_versions["ppg-11.5"]['binaries']
                         },
            "ppg-12.2": {"version": "12.2",
                         "deb_pkg_ver": ppg_versions["ppg-12.2"]['deb_pkg_ver'],
                         "deb_packages": ppg_versions["ppg-12.2"]['deb_packages'],
                         "percona-postgresql-common": '214',
                         "percona-postgresql-client-common": "214",
                         "libpq_version": "120002",
                         "pgaudit": pgaudit['ppg-12.2'],
                         "pgbackrest": pgbackrest['ppg-12.2'],
                         "patroni": patroni['ppg-12.2'],
                         "pgrepack": pgrepack['ppg-12.2'],
                         "libpq": "Version of libpq: 120002",
                         "deb_provides":  ppg_versions["ppg-12.2"]['deb_provides'],
                         "rpm7_provides": ppg_versions["ppg-12.2"]['rpm7_provides'],
                         'rpm_provides': ppg_versions["ppg-12.2"]['rpm_provides'],
                         "rpm_packages": ppg_versions["ppg-12.2"]['rpm_packages'],
                         "rpm7_packages": ppg_versions["ppg-12.2"]['rpm7_packages'],
                         "rhel_files": ppg_versions["ppg-12.2"]['rhel_files'],
                         "deb_files": ppg_versions["ppg-12.2"]['deb_files'],
                         "extensions": ppg_versions["ppg-12.2"]['extensions'],
                         "languages": ppg_versions["ppg-12.2"]['languages'],
                         "binaries": ppg_versions["ppg-12.2"]['binaries']
                         },
            "ppg-12.3": {"version": "12.3",
                         "deb_pkg_ver": ppg_versions["ppg-12.3"]['deb_pkg_ver'],
                         "deb_packages": ppg_versions["ppg-12.3"]['deb_packages'],
                         "percona-postgresql-common": '215',
                         "percona-postgresql-client-common": "215",
                         "libpq_version": "120003",
                         "pgaudit": pgaudit['ppg-12.3'],
                         "pgbackrest": pgbackrest['ppg-12.3'],
                         "patroni": patroni['ppg-12.3'],
                         "pgrepack": pgrepack['ppg-12.3'],
                         "pgrepack_package_rpm": 'percona-pg_repack12',
                         "pgrepack_package_deb": "percona-postgresql-12-repack",
                         "libpq": "Version of libpq: 120003",
                         "deb_provides":  ppg_versions["ppg-12.3"]['deb_provides'],
                         "rpm7_provides": ppg_versions["ppg-12.3"]['rpm7_provides'],
                         'rpm_provides': ppg_versions["ppg-12.3"]['rpm_provides'],
                         "rpm_packages": ppg_versions["ppg-12.3"]['rpm_packages'],
                         "rpm7_packages": ppg_versions["ppg-12.3"]['rpm7_packages'],
                         "rhel_files": ppg_versions["ppg-12.3"]['rhel_files'],
                         "deb_files": ppg_versions["ppg-12.3"]['deb_files'],
                         "extensions": ppg_versions["ppg-12.3"]['extensions'],
                         "languages": ppg_versions["ppg-12.3"]['languages'],
                         "binaries": ppg_versions["ppg-12.3"]['binaries']
                         },
            "ppg-12.4": {"version": "12.4",
                         "deb_pkg_ver": ppg_versions["ppg-12.4"]['deb_pkg_ver'],
                         "deb_packages": ppg_versions["ppg-12.4"]['deb_packages'],
                         "percona-postgresql-common": '216',
                         "percona-postgresql-client-common": "216",
                         "libpq_version": "120004",
                         "pgaudit": pgaudit['ppg-12.4'],
                         "pgbackrest": pgbackrest['ppg-12.4'],
                         "patroni": patroni['ppg-12.4'],
                         "pgrepack": pgrepack['ppg-12.4'],
                         "pgrepack_package_rpm": 'percona-pg_repack12',
                         "pgrepack_package_deb": "percona-postgresql-12-repack",
                         "libpq": "Version of libpq: 120004",
                         "deb_provides": ppg_versions["ppg-12.4"]['deb_provides'],
                         "rpm7_provides": ppg_versions["ppg-12.4"]['rpm7_provides'],
                         'rpm_provides': ppg_versions["ppg-12.4"]['rpm_provides'],
                         "rpm_packages": ppg_versions["ppg-12.4"]['rpm_packages'],
                         "rpm7_packages": ppg_versions["ppg-12.4"]['rpm7_packages'],
                         "rhel_files": ppg_versions["ppg-12.4"]['rhel_files'],
                         "deb_files": ppg_versions["ppg-12.4"]['deb_files'],
                         "extensions": ppg_versions["ppg-12.4"]['extensions'],
                         "languages": ppg_versions["ppg-12.4"]['languages'],
                         "binaries": ppg_versions["ppg-12.4"]['binaries']
                         },
            "ppg-12.5": {"version": "12.5",
                         "deb_pkg_ver": ppg_versions["ppg-12.5"]['deb_pkg_ver'],
                         "deb_packages": ppg_versions["ppg-12.5"]['deb_packages'],
                         "percona-postgresql-common": '223',
                         "percona-postgresql-client-common": "223",
                         "libpq_version": "120005",
                         "pgaudit": pgaudit['ppg-12.5'],
                         "pgbackrest": pgbackrest['ppg-12.5'],
                         "patroni": patroni['ppg-12.5'],
                         "pgrepack": pgrepack['ppg-12.5'],
                         "pgrepack_package_rpm": 'percona-pg_repack12',
                         "pgrepack_package_deb": "percona-postgresql-12-repack",
                         "libpq": "Version of libpq: 120005",
                         "deb_provides": ppg_versions["ppg-12.5"]['deb_provides'],
                         "rpm7_provides": ppg_versions["ppg-12.5"]['rpm7_provides'],
                         'rpm_provides': ppg_versions["ppg-12.5"]['rpm_provides'],
                         "rpm_packages": ppg_versions["ppg-12.5"]['rpm_packages'],
                         "rpm7_packages": ppg_versions["ppg-12.5"]['rpm7_packages'],
                         "rhel_files": ppg_versions["ppg-12.5"]['rhel_files'],
                         "deb_files": ppg_versions["ppg-12.5"]['deb_files'],
                         "extensions": ppg_versions["ppg-12.5"]['extensions'],
                         "languages": ppg_versions["ppg-12.5"]['languages'] ,
                         "binaries": ppg_versions["ppg-12.5"]['binaries']
                         },
            "ppg-12.6": {"version": "12.6",
                         "deb_pkg_ver": ppg_versions["ppg-12.6"]['deb_pkg_ver'],
                         "deb_packages": ppg_versions["ppg-12.6"]['deb_packages'],
                         "percona-postgresql-common": '225',
                         "percona-postgresql-client-common": "225",
                         "libpq_version": "120006",
                         "pgaudit": pgaudit['ppg-12.6'],
                         "pgbackrest": pgbackrest['ppg-12.6'],
                         "pgbadger": pgbadger['12.6'],
                         'pgbouncer': pgbouncer['12.6'],
                         "wal2json": wal2json['12.6'],
                         "set_user": set_user['12.6'],
                         "patroni": patroni['ppg-12.6'],
                         "pgrepack": pgrepack['ppg-12.6'],
                         "pgrepack_package_rpm": 'percona-pg_repack12',
                         "pgrepack_package_deb": "percona-postgresql-12-repack",
                         "libpq": "Version of libpq: 120006",
                         "deb_provides": ppg_versions["ppg-12.6"]['deb_provides'],
                         "rpm7_provides": ppg_versions["ppg-12.6"]['rpm7_provides'],
                         'rpm_provides': ppg_versions["ppg-12.6"]['rpm_provides'],
                         "rpm_packages": ppg_versions["ppg-12.6"]['rpm_packages'],
                         "rpm7_packages": ppg_versions["ppg-12.6"]['rpm7_packages'],
                         "rhel_files": ppg_versions["ppg-12.6"]['rhel_files'],
                         "deb_files": ppg_versions["ppg-12.6"]['deb_files'],
                         "extensions": ppg_versions["ppg-12.6"]['extensions'],
                         "languages": ppg_versions["ppg-12.6"]['languages'],
                         "binaries": ppg_versions["ppg-12.6"]['binaries'],
                         "pg_stat_monitor": "0.9.0"
                         },
            "ppg-12.7": {"version": "12.7",
                         "deb_pkg_ver": ppg_versions["ppg-12.7"]['deb_pkg_ver'],
                         "deb_packages": ppg_versions["ppg-12.7"]['deb_packages'],
                         "percona-postgresql-common": '226',
                         "percona-postgresql-client-common": "226",
                         "libpq_version": "120006",
                         "pgaudit": pgaudit['ppg-12.7'],
                         "pgbackrest": pgbackrest['ppg-12.7'],
                         "pgbadger": pgbadger['12.7'],
                         'pgbouncer': pgbouncer['12.7'],
                         "wal2json": wal2json['12.7'],
                         "set_user": set_user['12.7'],
                         "patroni": patroni['ppg-12.7'],
                         "pgrepack": pgrepack['ppg-12.7'],
                         "pgrepack_package_rpm": 'percona-pg_repack12',
                         "pgrepack_package_deb": "percona-postgresql-12-repack",
                         "libpq": "Version of libpq: 120007",
                         "deb_provides": ppg_versions["ppg-12.7"]['deb_provides'],
                         "rpm7_provides": ppg_versions["ppg-12.7"]['rpm7_provides'],
                         'rpm_provides': ppg_versions["ppg-12.7"]['rpm_provides'],
                         "rpm_packages": ppg_versions["ppg-12.7"]['rpm_packages'],
                         "rpm7_packages": ppg_versions["ppg-12.7"]['rpm7_packages'],
                         "rhel_files": ppg_versions["ppg-12.7"]['rhel_files'],
                         "deb_files": ppg_versions["ppg-12.7"]['deb_files'],
                         "extensions": ppg_versions["ppg-12.7"]['extensions'],
                         "languages": ppg_versions["ppg-12.7"]['languages'],
                         "binaries": ppg_versions["ppg-12.7"]['binaries'],
                         "pg_stat_monitor": "0.9.1"
                         },
            "ppg-13.0": {"version": "13.0",
                         "deb_pkg_ver": ppg_versions["ppg-13.0"]['deb_pkg_ver'],
                         "deb_packages": ppg_versions["ppg-13.0"]['deb_packages'],
                         "percona-postgresql-common": '221',
                         "percona-postgresql-client-common": "221",
                         "libpq_version": "130000",
                         "pgaudit": pgaudit['ppg-13.0'],
                         "pgbackrest": pgbackrest['ppg-13.0'],
                         "patroni": patroni['ppg-13.0'],
                         "pgrepack": pgrepack['ppg-13.0'],
                         "pgrepack_package_rpm": 'percona-pg_repack13',
                         "pgrepack_package_deb": "percona-postgresql-13-repack",
                         "libpq": "Version of libpq: 130000",
                         "deb_provides": ppg_versions["ppg-13.0"]['deb_provides'],
                         "rpm7_provides": ppg_versions["ppg-13.0"]['rpm7_provides'],
                         'rpm_provides': ppg_versions["ppg-13.0"]['rpm_provides'],
                         "rpm_packages": ppg_versions["ppg-13.0"]['rpm_packages'],
                         "rpm7_packages": ppg_versions["ppg-13.0"]['rpm7_packages'],
                         "rhel_files": ppg_versions["ppg-13.0"]['rhel_files'],
                         "deb_files": ppg_versions["ppg-13.0"]['deb_files'],
                         "extensions": ppg_versions["ppg-13.0"]['extensions'],
                         "languages": ppg_versions["ppg-13.0"]['languages'],
                         "binaries": ppg_versions["ppg-13.0"]['binaries']
                         },
            "ppg-13.1": {"version": "13.1",
                         "deb_pkg_ver": ppg_versions["ppg-13.1"]['deb_pkg_ver'],
                         "deb_packages": ppg_versions["ppg-13.1"]['deb_packages'],
                         "percona-postgresql-common": '223',
                         "percona-postgresql-client-common": "223",
                         "libpq_version": "130000",
                         "pgaudit": pgaudit['ppg-13.1'],
                         "pgbackrest": pgbackrest['ppg-13.1'],
                         "patroni": patroni['ppg-13.1'],
                         "pgrepack": pgrepack['ppg-13.1'],
                         "pgrepack_package_rpm": 'percona-pg_repack13',
                         "pgrepack_package_deb": "percona-postgresql-13-repack",
                         "libpq": "Version of libpq: 130001",
                         "deb_provides": ppg_versions["ppg-13.1"]['deb_provides'],
                         "rpm7_provides": ppg_versions["ppg-13.1"]['rpm7_provides'],
                         'rpm_provides': ppg_versions["ppg-13.1"]['rpm_provides'],
                         "rpm_packages": ppg_versions["ppg-13.1"]['rpm_packages'],
                         "rpm7_packages": ppg_versions["ppg-13.1"]['rpm7_packages'],
                         "rhel_files": ppg_versions["ppg-13.1"]['rhel_files'],
                         "deb_files": ppg_versions["ppg-13.1"]['deb_files'],
                         "extensions": ppg_versions["ppg-13.1"]['extensions'],
                         "languages": ppg_versions["ppg-13.1"]['languages'],
                         "binaries": ppg_versions["ppg-13.1"]['binaries']
            },
            "ppg-13.2": {"version": "13.2",
                         "deb_pkg_ver": ppg_versions["ppg-13.2"]['deb_pkg_ver'],
                         "deb_packages": ppg_versions["ppg-13.2"]['deb_packages'],
                         "percona-postgresql-common": '225',
                         "percona-postgresql-client-common": "225",
                         "libpq_version": "130002",
                         "pgaudit": pgaudit['ppg-13.2'],
                         "pgbackrest": pgbackrest['ppg-13.2'],
                         "patroni": patroni['ppg-13.2'],
                         "pgrepack": pgrepack['ppg-13.2'],
                         "pgbadger": pgbadger['13.2'],
                         'pgbouncer': pgbouncer['13.2'],
                         "wal2json": wal2json['13.2'],
                         "set_user": set_user['13.2'],
                         "pgrepack_package_rpm": 'percona-pg_repack13',
                         "pgrepack_package_deb": "percona-postgresql-13-repack",
                         "libpq": "Version of libpq: 130002",
                         "deb_provides": ppg_versions["ppg-13.2"]['deb_provides'],
                         "rpm7_provides": ppg_versions["ppg-13.2"]['rpm7_provides'],
                         'rpm_provides': ppg_versions["ppg-13.2"]['rpm_provides'],
                         "rpm_packages": ppg_versions["ppg-13.2"]['rpm_packages'],
                         "rpm7_packages": ppg_versions["ppg-13.2"]['rpm7_packages'],
                         "rhel_files": ppg_versions["ppg-13.2"]['rhel_files'],
                         "deb_files": ppg_versions["ppg-13.2"]['deb_files'],
                         "extensions": ppg_versions["ppg-13.2"]['extensions'],
                         "languages": ppg_versions["ppg-13.2"]['languages'],
                         "binaries": ppg_versions["ppg-13.2"]['binaries'],
                         "pg_stat_monitor": "0.9.0"},
            "ppg-13.3": {"version": "13.3",
                         "deb_pkg_ver": ppg_versions["ppg-13.3"]['deb_pkg_ver'],
                         "deb_packages": ppg_versions["ppg-13.3"]['deb_packages'],
                         "percona-postgresql-common": '226',
                         "percona-postgresql-client-common": "226",
                         "libpq_version": "130002",
                         "pgaudit": pgaudit['ppg-13.3'],
                         "pgbackrest": pgbackrest['ppg-13.3'],
                         "patroni": patroni['ppg-13.3'],
                         "pgrepack": pgrepack['ppg-13.3'],
                         "pgbadger": pgbadger['13.3'],
                         'pgbouncer': pgbouncer['13.3'],
                         "wal2json": wal2json['13.3'],
                         "set_user": set_user['13.3'],
                         "pgrepack_package_rpm": 'percona-pg_repack13',
                         "pgrepack_package_deb": "percona-postgresql-13-repack",
                         "libpq": "Version of libpq: 130003",
                         "deb_provides": ppg_versions["ppg-13.3"]['deb_provides'],
                         "rpm7_provides": ppg_versions["ppg-13.3"]['rpm7_provides'],
                         'rpm_provides': ppg_versions["ppg-13.3"]['rpm_provides'],
                         "rpm_packages": ppg_versions["ppg-13.3"]['rpm_packages'],
                         "rpm7_packages": ppg_versions["ppg-13.3"]['rpm7_packages'],
                         "rhel_files": ppg_versions["ppg-13.3"]['rhel_files'],
                         "deb_files": ppg_versions["ppg-13.3"]['deb_files'],
                         "extensions": ppg_versions["ppg-13.3"]['extensions'],
                         "languages": ppg_versions["ppg-13.3"]['languages'],
                         "binaries": ppg_versions["ppg-13.3"]['binaries'],
                         "pg_stat_monitor": "0.9.1"}
    }

