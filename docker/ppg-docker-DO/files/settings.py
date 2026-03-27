import os

pgrepack = {
    "16.13": {"version": "1.5.3","binary_version": "pg_repack 1.5.3"},
    "17.9": {"version": "1.5.3","binary_version": "pg_repack 1.5.3"},
    "18.3": {"version": "1.5.3","binary_version": "pg_repack 1.5.3"},
}

pgaudit = {
    "16.13": {"version": "16.1"},
    "17.9": {"version": "17.1"},
    "18.3": {"version": "18.0"},
}

pg_stat_monitor = {
    "16.13": {"version": "2.3.2"},
    "17.9": {"version": "2.3.2"},
    "18.3": {"version": "2.3.2"},
}

set_user = {
    "16.13": {"version": "4.2.0"},
    "17.9": {"version": "4.2.0"},
    "18.3": {"version": "4.2.0"},
}

wal2json = {
    "16.13": {"version": "2.6"},
    "17.9": {"version": "2.6"},
    "18.3": {"version": "2.6"},
}

patroni = {
    "16.13": {"version": "4.1.0","binary_version": "patroni 4.1.0"},
    "17.9": {"version": "4.1.0","binary_version": "patroni 4.1.0"},
    "18.3": {"version": "4.1.0","binary_version": "patroni 4.1.0"},
}

pgbackrest = {
    "16.13": {"version": "2.58.0","binary_version": "pgBackRest 2.58.0"},
    "17.9": {"version": "2.58.0","binary_version": "pgBackRest 2.58.0"},
    "18.3": {"version": "2.58.0","binary_version": "pgBackRest 2.58.0"},
}

pgvector = {
    "16.13": {"version": "0.8.2", "extension_version": "0.8.2"},
    "17.9": {"version": "0.8.2", "extension_version": "0.8.2"},
    "18.3": {"version": "0.8.2", "extension_version": "0.8.2"},
}

postgis = {
    "16.13": {"version": "3.5.5", "major_version": "3.5", "extension_version": "3.5.5"},
    "17.9": {"version": "3.5.5", "major_version": "3.5", "extension_version": "3.5.5"},
    "18.3": {"version": "3.5.5", "major_version": "3.5", "extension_version": "3.5.5"},
}


pg_telemetry = {
    "16.13": {"pg_telemetry_version": "1.2","pg_telemetry_package_version": "1.2.0"},
    "17.9": {"pg_telemetry_version": "1.2","pg_telemetry_package_version": "1.2.0"},
    "18.3": {"pg_telemetry_version": "1.2","pg_telemetry_package_version": "1.2.0"},
}

python3_etcd = {
    "16.13": {"version": "0.4.5"},
    "17.9": {"version": "0.4.5"},
    "18.3": {"version": "0.4.5"},
}

python3_psycopg2 = {
    "16.13": {"version": "2.9.11"},
    "17.9": {"version": "2.9.11"},
    "18.3": {"version": "2.9.11"},
}

python3_ydiff = {
    "16.13": {"version": "1.4.2"},
    "17.9": {"version": "1.4.2"},
    "18.3": {"version": "1.4.2"},
}

ydiff = {
    "16.13": {"version": "1.4.2"},
    "17.9": {"version": "1.4.2"},
    "18.3": {"version": "1.4.2"},
}

python3_12_click = {
    "16.13": {"version": "8.1.7"},
    "17.9": {"version": "8.1.7"},
    "18.3": {"version": "8.1.7"},
}     
python3_12_dateutil = {
    "16.13": {"version": "2.9.0"},
    "17.9": {"version": "2.9.0"},
    "18.3": {"version": "2.9.0"},
}
python3_12_prettytable = {
    "16.13": {"version": "3.4.0"},
    "17.9": {"version": "3.4.0"},
    "18.3": {"version": "3.4.0"},
}
python3_12_psutil = {
    "16.13": {"version": "6.1.1"},
    "17.9": {"version": "6.1.1"},
    "18.3": {"version": "6.1.1"},
}
python3_12_psycopg2 = {
    "16.13": {"version": "2.9.10"},
    "17.9": {"version": "2.9.10"},
    "18.3": {"version": "2.9.10"},
}
python3_12_six = {
    "16.13": {"version": "1.17.0"},
    "17.9": {"version": "1.17.0"},
    "18.3": {"version": "1.17.0"},
}
python3_12_wcwidth = {
    "16.13": {"version": "0.2.13"},
    "17.9": {"version": "0.2.13"},
    "18.3": {"version": "0.2.13"},
}
timescaledb = {
    "16.13": {"version": "2.26.0"},
    "17.9": {"version": "2.26.0"},
    "18.3": {"version": "2.26.0"},
}

# DOCKER_LIST_EXTENSIONS = ["hstore",
#                 "adminpack",
#                 "amcheck",
#                 "cube",
#                 "insert_username",
#                 "autoinc",
#                 "bloom",
#                 "earthdistance",
#                 "intagg",
#                 "btree_gin",
#                 "file_fdw",
#                 "fuzzystrmatch",
#                 "btree_gist",
#                 "intarray",
#                 "citext",
#                 "dblink",
#                 "dict_xsyn",
#                 "lo",
#                 "dict_int",
#                 "isn",
#                 "ltree",
#                 "moddatetime",
#                 "pgrowlocks",
#                 "pageinspect",
#                 "pg_trgm",
#                 "tcn",
#                 "pgstattuple",
#                 "pg_buffercache",
#                 "xml2",
#                 "postgres_fdw",
#                 "pg_freespacemap",
#                 "pg_prewarm",
#                 "pg_visibility",
#                 "refint",
#                 "pgcrypto",
#                 "pg_stat_statements",
#                 "seg",
#                 "sslinfo",
#                 "tablefunc",
#                 "tsm_system_rows",
#                 "tsm_system_time",
#                 "unaccent",
#                 "uuid-ossp",
#                 "pg_stat_monitor",
#                 "vector",
#                 "postgis_sfcgal",
#                 "address_standardizer",
#                 "postgis_tiger_geocoder",
#                 "postgis",
#                 "postgis_topology",
#                 "postgis_raster",
#                 "address_standardizer_data_us"
#                 ]

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
                "pg_stat_monitor",
                "vector",
                "postgis_sfcgal",
                "address_standardizer",
                "postgis_tiger_geocoder",
                "postgis",
                "postgis_topology",
                "postgis_raster",
                "address_standardizer_data_us",
                "pg_logicalinspect",
                "pg_repack",
                "pgaudit",
                "plpgsql",
                 ]

# DOCKER_RPM_PACKAGES_TEMPLATE = ["postgresql{}",
#                                 "postgresql{}-contrib",
#                                 "postgresql{}-libs",
#                                 "postgresql{}-server",
#                                 "wal2json{}",
#                                 "pg_stat_monitor{}",
#                                 "pgaudit{}",
#                                 "pgaudit{}_set_user",
#                                 "pg_repack{}",
#                                 "postgresql{}-llvmjit",
#                                 "patroni",
#                                 "pgbackrest",
#                                 "pgvector_{}",
#                                 "pgvector_{}-llvmjit",
#                                 "postgis35_{}",
#                                 "postgis35_{}-client",
#                                 "postgis35_{}-gui",
#                                 "postgis35_{}-llvmjit",
#                                 "postgis35_{}-utils",
#                                 "python3-etcd",
#                                 "python3-ydiff", 
#                                 "python3-psycopg2",
#                                 "python3-ydiff",
#                                 "python3.12-click",
#                                 "python3.12-dateutil",
#                                 "python3.12-prettytable",
#                                 "python3.12-psutil",
#                                 "python3.12-psycopg2",
#                                 "python3.12-six",
#                                 "python3.12-wcwidth",
#                                 "timescaledb-2-loader-postgresql-{}",
#                                 "timescaledb-2-oss-postgresql-{}",
#                                 "timescaledb-tools"
#                              ]


                                # "python3-psycopg2",
                                # "python3-ydiff",
                                # "python3.12-click",
                                # "python3.12-dateutil",
                                # "python3.12-prettytable",
                                # "python3.12-psutil",
                                # "python3.12-psycopg2",
                                # "python3.12-six",
                                # "python3.12-wcwidth",

DOCKER_RPM_PACKAGES_TEMPLATE = ["percona-postgresql{}",
                                "percona-postgresql{}-contrib",
                                "percona-postgresql-common",
                                "percona-postgresql{}-libs",
                                "percona-postgresql{}-server",
                                "percona-postgresql-client-common",
                                "percona-wal2json{}",
                                "percona-pg_stat_monitor{}",
                                "percona-pgaudit{}",
                                "percona-pgaudit{}_set_user",
                                "percona-pg_repack{}",
                                "percona-postgresql{}-llvmjit",
                                "percona-patroni",
                                "percona-pgbackrest",
                                "percona-pgvector_{}",
                                "percona-pgvector_{}-llvmjit",
                                "percona-postgis35_{}",
                                "percona-postgis35_{}-client",
                                "percona-postgis35_{}-gui",
                                "percona-postgis35_{}-llvmjit",
                                "percona-postgis35_{}-utils",
                                "python3-etcd",
                                "python3-ydiff",
                                "percona-timescaledb_{}"
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
        "16.13": {
            "version": "16.13",
            "percona-postgresql-common": "289",
            "percona-postgresql-client-common": "289",
            "libpq_version": "160013",
            "percona-pgaudit16": pgaudit["16.13"],
            "percona-pg_repack16": pgrepack["16.13"],
            "percona-wal2json16": wal2json["16.13"],
            "percona-pgaudit16_set_user": set_user["16.13"],
            "percona-pg_stat_monitor16" : pg_stat_monitor["16.13"],
            "percona-pg-telemetry" : pg_telemetry["16.13"],
            "libpq": "Version of libpq: 160013",
            "percona-patroni": patroni["16.13"],
            "percona-pgbackrest": pgbackrest["16.13"],
            "percona-pgvector_16": pgvector["16.13"],
            "percona-pgvector_16-llvmjit": pgvector["16.13"],
            "python3-etcd": python3_etcd["16.13"],
            # "python3-pysyncobj": python3_pysyncobj["16.13"],
            "python3-ydiff": python3_ydiff["16.13"],
            # "ydiff": ydiff["16.13"],
            "percona-postgis35_16": postgis["16.13"],
            "percona-postgis35_16-client": postgis["16.13"],
            "percona-postgis35_16-gui": postgis["16.13"],
            "percona-postgis35_16-llvmjit": postgis["16.13"],
            "percona-postgis35_16-utils": postgis["16.13"],
            "percona-timescaledb_16": timescaledb["16.13"],
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
        "17.9": {
            "version": "17.9",
            "percona-version": "17.9.1",
            "percona-postgresql-common": "289",
            "percona-postgresql-client-common": "289",
            "libpq_version": "170009",
            "percona-pgaudit17": pgaudit["17.9"],
            "percona-pg_repack17": pgrepack["17.9"],
            "percona-wal2json17": wal2json["17.9"],
            "percona-pgaudit17_set_user": set_user["17.9"],
            "percona-pg_stat_monitor17" : pg_stat_monitor["17.9"],
            "percona-pg-telemetry" : pg_telemetry["17.9"],
            "libpq": "Version of libpq: 170009",
            "percona-patroni": patroni["17.9"],
            "percona-pgbackrest": pgbackrest["17.9"],
            "percona-pgvector_17": pgvector["17.9"],
            "percona-pgvector_17-llvmjit": pgvector["17.9"],
            "python3-etcd": python3_etcd["17.9"],
            #"python3-pysyncobj": python3_pysyncobj["17.9"],
            "python3-ydiff": python3_ydiff["17.9"],
            #"ydiff": ydiff["17.9"],
            "percona-postgis35_17": postgis["17.9"],
            "percona-postgis35_17-client": postgis["17.9"],
            "percona-postgis35_17-gui": postgis["17.9"],
            "percona-postgis35_17-llvmjit": postgis["17.9"],
            "percona-postgis35_17-utils": postgis["17.9"],
            "percona-timescaledb_17": timescaledb["17.9"],
            "rpm_packages": fill_template_form(DOCKER_RPM_PACKAGES_TEMPLATE, "17"),
            "rhel_files": fill_template_form(DOCKER_RHEL_FILES_TEMPLATE, "17"),
            "extensions": DOCKER_LIST_EXTENSIONS,
            "binaries": ['clusterdb', 'createdb', 'createuser',
                        'dropdb', 'dropuser', 'pg_basebackup',
                        'pg_config', 'pg_dump', 'pg_dumpall',
                        'pg_isready', 'pg_receivewal', 'pg_recvlogical',
                        'pg_restore', 'pg_verifybackup', 'psql',
                        'reindexdb', 'vacuumdb']
        },
        "18.3": {
            "version": "18.3",
            "percona-version": "18.3.1",
            "percona-postgresql-common": "289",
            "percona-postgresql-client-common": "289",
            "libpq_version": "180003",
            "percona-pgaudit18": pgaudit["18.3"],
            "percona-pg_repack18": pgrepack["18.3"],
            "percona-wal2json18": wal2json["18.3"],
            "percona-pgaudit18_set_user": set_user["18.3"],
            "percona-pg_stat_monitor18" : pg_stat_monitor["18.3"],
            "percona-pg-telemetry" : pg_telemetry["18.3"],
            "libpq": "Version of libpq: 180009",
            "percona-patroni": patroni["18.3"],
            "percona-pgbackrest": pgbackrest["18.3"],
            "percona-pgvector_18": pgvector["18.3"],
            "percona-pgvector_18-llvmjit": pgvector["18.3"],
            "python3-etcd": python3_etcd["18.3"],
            #"python3-pysyncobj": python3_pysyncobj["18.3"],
            "python3-ydiff": python3_ydiff["18.3"],
            #"ydiff": ydiff["18.3"],
            "percona-postgis35_18": postgis["18.3"],
            "percona-postgis35_18-client": postgis["18.3"],
            "percona-postgis35_18-gui": postgis["18.3"],
            "percona-postgis35_18-llvmjit": postgis["18.3"],
            "percona-postgis35_18-utils": postgis["18.3"],
            "percona-timescaledb_18": timescaledb["18.3"],
            "libpq": "Version of libpq: 180003",
            "rpm_packages": fill_template_form(DOCKER_RPM_PACKAGES_TEMPLATE, "18"),
            "rhel_files": fill_template_form(DOCKER_RHEL_FILES_TEMPLATE, "18"),
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
