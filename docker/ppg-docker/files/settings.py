import os

pgrepack = {
    "12.16": {"version": "1.4.8", "binary_version": "pg_repack 1.4.8"},
    "13.12": {"version": "1.4.8", "binary_version": "pg_repack 1.4.8"},
    "14.9": {"version": "1.4.8", "binary_version": "pg_repack 1.4.8"},
    "15.4": {"version": "1.4.8", "binary_version": "pg_repack 1.4.8"},
    "16.0": {"version": "1.4.8", "binary_version": "pg_repack 1.4.8"},
}

pgaudit = {
    "12.16": {"version": "1.4.3"},
    "13.12": {"version": "1.5.2"},
    "14.9": {"version": "1.6.2"},
    "15.4": {"version": "1.7.0"},
    "16.0": {"version": "16.0"},
}

pg_stat_monitor = {
    "12.16": {"version": "2.0.1"},
    "13.12": {"version": "2.0.1"},
    "14.9": {"version": "2.0.1"},
    "15.4": {"version": "2.0.1"},
    "16.0": {"version": "2.0.2"},
}

set_user = {
    "12.16": {"version": "4.0.1"},
    "13.12": {"version": "4.0.1"},
    "14.9": {"version": "4.0.1"},
    "15.4": {"version": "4.0.1"},
    "16.0": {"version": "4.0.1"},
}

wal2json = {
    "12.16": {"version": "2.5"},
    "13.12": {"version": "2.5"},
    "14.9": {"version": "2.5"},
    "15.4": {"version": "2.5"},
    "16.0": {"version": "2.5"},
}


DOCKER_LIST_EXTENSIONS = ["hstore",
                "adminpack",
                "amcheck",
                "cube",
                "insert_username",
                "autoinc",
                "bloom",
                "earthdistance",
                "intagg",
                "btree_gin",
                "file_fdw",
                "fuzzystrmatch",
                "btree_gist",
                "intarray",
                "citext",
                "dblink",
                "dict_xsyn",
                "lo",
                "dict_int",
                "isn",
                "ltree",
                "moddatetime",
                "pgrowlocks",
                "pageinspect",
                "pg_trgm",
                "tcn",
                "pgstattuple",
                "pg_buffercache",
                "xml2",
                "postgres_fdw",
                "pg_freespacemap",
                "pg_prewarm",
                "pg_visibility",
                "refint",
                "pgcrypto",
                "pg_stat_statements",
                "seg",
                "sslinfo",
                "tablefunc",
                "tsm_system_rows",
                "tsm_system_time",
                "unaccent",
                "uuid-ossp",
                "pg_stat_monitor"
                ]

DOCKER_RPM_PACKAGES_TEMPLATE = ["percona-postgresql{}",
                             "percona-postgresql{}-contrib",
                             "percona-postgresql-common",
                             "percona-postgresql{}-libs",
                             #"percona-postgresql{}-llvmjit",
                             "percona-postgresql{}-server",
                             "percona-postgresql-client-common",
                             "percona-wal2json{}",
                             "percona-pg_stat_monitor{}",
                             "percona-pgaudit",
                             "percona-pgaudit{}_set_user",
                             "percona-pg_repack{}",
                             ]


DOCKER_RHEL_FILES_TEMPLATE = ["/data/db/postgresql.conf",
                       "/data/db/pg_hba.conf",
                       "/data/db/pg_ident.conf"]


def fill_template_form(template, pg_version):
    """

    :param template:
    :param pg_version:
    :return:
    """
    return [t.format(pg_version) for t in template]

def fill_provides_template_form(provides_template, pg_version):
    """

    :param provides_template:
    :param pg_version:
    :return:
    """
    return [(t[0].format(pg_version), t[1].format(pg_version)) for t in provides_template]


ppg_versions = {
        "12.16": {
            "version": "12.16",
            "percona-postgresql-common": "252",
            "percona-postgresql-client-common": "252",
            "libpq_version": "120016",
            "percona-pgaudit": pgaudit["12.16"],
            "percona-pg_repack12": pgrepack["12.16"],
            "percona-wal2json12": wal2json["12.16"],
            "percona-pgaudit12_set_user": set_user["12.16"],
            "percona-pg_stat_monitor12" : pg_stat_monitor["12.16"],
            "libpq": "Version of libpq: 120016",
            "rpm_packages": fill_template_form(DOCKER_RPM_PACKAGES_TEMPLATE, "12"),
            "rhel_files": fill_template_form(DOCKER_RHEL_FILES_TEMPLATE, "12"),
            "extensions": DOCKER_LIST_EXTENSIONS,
            "binaries": ['clusterdb', 'createdb', 'createuser',
                        'dropdb', 'dropuser', 'pg_basebackup',
                        'pg_config', 'pg_dump', 'pg_dumpall',
                        'pg_isready', 'pg_receivewal', 'pg_recvlogical',
                        'pg_restore', 'psql', 'reindexdb', 'vacuumdb']
        },
        "13.12": {
            "version": "13.12",
            "percona-postgresql-common": "252",
            "percona-postgresql-client-common": "252",
            "libpq_version": "130012",
            "percona-pgaudit": pgaudit["13.12"],
            "percona-pg_repack13": pgrepack["13.12"],
            "percona-wal2json13": wal2json["13.12"],
            "percona-pgaudit13_set_user": set_user["13.12"],
            "percona-pg_stat_monitor13" : pg_stat_monitor["13.12"],
            "libpq": "Version of libpq: 130012",
            "rpm_packages": fill_template_form(DOCKER_RPM_PACKAGES_TEMPLATE, "13"),
            "rhel_files": fill_template_form(DOCKER_RHEL_FILES_TEMPLATE, "13"),
            "extensions": DOCKER_LIST_EXTENSIONS,
            "binaries": ['clusterdb', 'createdb', 'createuser',
                        'dropdb', 'dropuser', 'pg_basebackup',
                        'pg_config', 'pg_dump', 'pg_dumpall',
                        'pg_isready', 'pg_receivewal', 'pg_recvlogical',
                        'pg_restore', 'pg_verifybackup', 'psql',
                        'reindexdb', 'vacuumdb']
        },
        "14.9": {
            "version": "14.9",
            "percona-postgresql-common": "252",
            "percona-postgresql-client-common": "252",
            "libpq_version": "140009",
            "percona-pgaudit": pgaudit["14.9"],
            "percona-pg_repack14": pgrepack["14.9"],
            "percona-wal2json14": wal2json["14.9"],
            "percona-pgaudit14_set_user": set_user["14.9"],
            "percona-pg_stat_monitor14" : pg_stat_monitor["14.9"],
            "libpq": "Version of libpq: 140009",
            "rpm_packages": fill_template_form(DOCKER_RPM_PACKAGES_TEMPLATE, "14"),
            "rhel_files": fill_template_form(DOCKER_RHEL_FILES_TEMPLATE, "14"),
            "extensions": DOCKER_LIST_EXTENSIONS,
            "binaries": ['clusterdb', 'createdb', 'createuser',
                        'dropdb', 'dropuser', 'pg_basebackup',
                        'pg_config', 'pg_dump', 'pg_dumpall',
                        'pg_isready', 'pg_receivewal', 'pg_recvlogical',
                        'pg_restore', 'pg_verifybackup', 'psql',
                        'reindexdb', 'vacuumdb']
        },
        "15.4": {
            "version": "15.4",
            "percona-postgresql-common": "252",
            "percona-postgresql-client-common": "252",
            "libpq_version": "150004",
            "percona-pgaudit": pgaudit["15.4"],
            "percona-pg_repack15": pgrepack["15.4"],
            "percona-wal2json15": wal2json["15.4"],
            "percona-pgaudit15_set_user": set_user["15.4"],
            "percona-pg_stat_monitor15" : pg_stat_monitor["15.4"],
            "libpq": "Version of libpq: 150004",
            "rpm_packages": fill_template_form(DOCKER_RPM_PACKAGES_TEMPLATE, "15"),
            "rhel_files": fill_template_form(DOCKER_RHEL_FILES_TEMPLATE, "15"),
            "extensions": DOCKER_LIST_EXTENSIONS,
            "binaries": ['clusterdb', 'createdb', 'createuser',
                        'dropdb', 'dropuser', 'pg_basebackup',
                        'pg_config', 'pg_dump', 'pg_dumpall',
                        'pg_isready', 'pg_receivewal', 'pg_recvlogical',
                        'pg_restore', 'pg_verifybackup', 'psql',
                        'reindexdb', 'vacuumdb']
        },
        "16.0": {
            "version": "16.0",
            "percona-postgresql-common": "253",
            "percona-postgresql-client-common": "253",
            "libpq_version": "160000",
            "percona-pgaudit": pgaudit["16.0"],
            "percona-pg_repack16": pgrepack["16.0"],
            "percona-wal2json16": wal2json["16.0"],
            "percona-pgaudit16_set_user": set_user["16.0"],
            "percona-pg_stat_monitor16" : pg_stat_monitor["16.0"],
            "libpq": "Version of libpq: 160000",
            "rpm_packages": fill_template_form(DOCKER_RPM_PACKAGES_TEMPLATE, "16"),
            "rhel_files": fill_template_form(DOCKER_RHEL_FILES_TEMPLATE, "16"),
            "extensions": DOCKER_LIST_EXTENSIONS,
            "binaries": ['clusterdb', 'createdb', 'createuser',
                        'dropdb', 'dropuser', 'pg_basebackup',
                        'pg_config', 'pg_dump', 'pg_dumpall',
                        'pg_isready', 'pg_receivewal', 'pg_recvlogical',
                        'pg_restore', 'pg_verifybackup', 'psql',
                        'reindexdb', 'vacuumdb']
        },
    }

def get_settings(ppg_version):
    return ppg_versions[ppg_version]