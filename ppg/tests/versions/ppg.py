from .extensions import get_extensions

DISTROS = ['bullseye', 'jammy', 'bookworm', 'noble', 'trixie', 'resolute']
DEB12_PACKAGES_TEMPLATE = [
    "percona-postgresql-{}",
    "percona-postgresql-client",
    "percona-postgresql",
    "percona-postgresql-client-{}",
    "percona-postgresql-contrib",
    "percona-postgresql-doc",
    "percona-postgresql-server-dev-all",
    "percona-postgresql-doc-{}",
    "percona-postgresql-plperl-{}",
    "percona-postgresql-common",
    "percona-postgresql-plpython3-{}",
    "percona-postgresql-pltcl-{}",
    "percona-postgresql-all",
    "percona-postgresql-server-dev-{}",
    "percona-postgresql-{}-dbgsym",
    "percona-postgresql-client-{}-dbgsym",
    "percona-postgresql-plperl-{}-dbgsym",
    "percona-postgresql-plpython3-{}-dbgsym",
    "percona-postgresql-pltcl-{}-dbgsym",
    "postgresql-common",
    "postgresql-client-common"
]

RPM7_PG13PACKAGES_TEMPLATE = ["percona-postgresql{}",
                              "percona-postgresql{}-contrib",
                              "percona-postgresql-common",
                              "percona-postgresql{}-debuginfo",
                              "percona-postgresql{}-devel",
                              "percona-postgresql{}-docs",
                              "percona-postgresql{}-libs",
                              "percona-postgresql{}-llvmjit",
                              "percona-postgresql{}-plperl",
                              "percona-postgresql{}-plpython3",
                              "percona-postgresql{}-pltcl",
                              "percona-postgresql{}-server",
                              "percona-postgresql{}-test",
                              "percona-postgresql-client-common"]

RPM_PG13PACKAGES_TEMPLATE = ["percona-postgresql{}",
                             "percona-postgresql{}-contrib",
                             "percona-postgresql-common",
                             "percona-postgresql{}-debuginfo",
                             "percona-postgresql{}-devel",
                             "percona-postgresql{}-docs",
                             "percona-postgresql{}-libs",
                             "percona-postgresql{}-llvmjit",
                             "percona-postgresql{}-plperl",
                             "percona-postgresql{}-plpython3",
                             "percona-postgresql{}-pltcl",
                             "percona-postgresql{}-server",
                             "percona-postgresql{}-test",
                             "percona-postgresql-client-common",
                             "percona-postgresql{}-debuginfo",
                             "percona-postgresql{}-debugsource",
                             "percona-postgresql{}-devel-debuginfo",
                             "percona-postgresql{}-libs-debuginfo",
                             "percona-postgresql{}-plperl-debuginfo",
                             "percona-postgresql{}-plpython3-debuginfo",
                             "percona-postgresql{}-pltcl-debuginfo",
                             "percona-postgresql{}-server-debuginfo",
                             ]

DEB_FILES_TEMPLATE = ["/etc/postgresql/{}/main/postgresql.conf",
                      "/etc/postgresql/{}/main/pg_hba.conf",
                      "/etc/postgresql/{}/main/pg_ctl.conf",
                      "/etc/postgresql/{}/main/pg_ident.conf"]

RHEL_FILES_TEMPLATE = ["/var/lib/pgsql/{}/data/postgresql.conf",
                       "/var/lib/pgsql/{}/data/pg_hba.conf",
                       "/var/lib/pgsql/{}/data/pg_ident.conf"]

LANGUAGES = ["pltcl", "pltclu", "plperl", "plperlu", "plpythonu", "plpython2u", "plpython3u"]

DEB_PROVIDES_TEMPLATE = [("percona-postgresql-{}", "postgresql-{}"),
                         ("percona-postgresql-client", "postgresql-client"),
                         ("percona-postgresql", "postgresql"),
                         ("percona-postgresql-client-{}", "postgresql-client-{}"),
                         ("percona-postgresql-contrib", "postgresql-contrib"),
                         ("percona-postgresql-doc", "postgresql-doc"),
                         ("percona-postgresql-server-dev-all", "postgresql-server-dev-all"),
                         ('percona-postgresql-plperl-{}', 'postgresql-plperl-{}'),
                         ("percona-postgresql-plpython3-{}", "postgresql-plpython3"),
                         ("percona-postgresql-pltcl-{}", "postgresql-{}-pltcl"),
                         ("percona-postgresql-all", "postgresql-all")
                         ]

RPM7_PROVIDES_TEMPLATE = [("percona-postgresql{}", 'postgresql{}'),
                          ("percona-postgresql{}-contrib", 'postgresql{}-contrib'),
                          ("percona-postgresql-common", 'postgresql-common'),
                          ("percona-postgresql{}-devel", 'postgresql{}-devel'),
                          ("percona-postgresql{}-docs", "postgresql-docs"),
                          ("percona-postgresql{}-libs", 'postgresql{}-libs'),
                          ("percona-postgresql{}-llvmjit", 'postgresql{}-llvmjit'),
                          ('percona-postgresql{}-plperl', 'postgresql{}-plperl'),
                          ("percona-postgresql{}-pltcl", 'postgresql{}-pltcl'),
                          ("percona-postgresql{}-plpython3", 'postgresql-plpython3'),
                          ('percona-postgresql{}-server', 'postgresql{}-server'),
                          ("percona-postgresql{}-test", 'postgresql{}-test'),
                          ("percona-postgresql-client-common", 'postgresql-client-common')]

RPM_PROVIDES_TEMPLATE = [("percona-postgresql{}", "postgresql{}"),
                         ("percona-postgresql{}-contrib", "postgresql{}-contrib"),
                         ("percona-postgresql-common", "postgresql-common"),
                         ("percona-postgresql{}-devel", "postgresql-devel"),
                         ("percona-postgresql{}-docs", "postgresql-docs"),
                         ("percona-postgresql{}-libs", "postgresql{}-libs"),
                         ("percona-postgresql{}-llvmjit", "postgresql{}-llvmjit"),
                         ("percona-postgresql{}-plperl", 'postgresql{}-plperl'),
                         ("percona-postgresql{}-plpython3", 'postgresql-plpython3'),
                         ("percona-postgresql{}-pltcl", 'postgresql{}-pltcl'),
                         ("percona-postgresql{}-server", 'postgresql{}-server'),
                         ("percona-postgresql{}-test", "postgresql{}-test"),
                         ("percona-postgresql-client-common", 'postgresql-client-common')
                         ]


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


def fill_package_versions(packages, distros):
    result = []
    for d in distros:
        for p in packages:
            result.append(".".join([p, d]))
    return result


def get_pg14_versions(distros, packages, distro_type):
    ppg_14_versions = {
                       "deb_packages": fill_template_form(DEB12_PACKAGES_TEMPLATE, "14"),
                       "deb_provides": fill_provides_template_form(DEB_PROVIDES_TEMPLATE, "14"),
                       "rpm7_provides": fill_provides_template_form(RPM7_PROVIDES_TEMPLATE, "14"),
                       'rpm_provides': fill_provides_template_form(RPM_PROVIDES_TEMPLATE, "14"),
                       "rpm_packages": fill_template_form(RPM_PG13PACKAGES_TEMPLATE, "14"),
                       "rpm7_packages": fill_template_form(RPM7_PG13PACKAGES_TEMPLATE, "14"),
                       "rhel_files": fill_template_form(RHEL_FILES_TEMPLATE, "14"),
                       "deb_files": fill_template_form(DEB_FILES_TEMPLATE, "14"),
                       "extensions": get_extensions(distro_type),
                       "binaries": ['clusterdb', 'createdb', 'createuser',
                                    'dropdb', 'dropuser', 'pg_basebackup',
                                    'pg_config', 'pg_dump', 'pg_dumpall',
                                    'pg_isready', 'pg_receivewal', 'pg_recvlogical',
                                    'pg_restore', 'pg_verifybackup', 'psql',
                                    'reindexdb', 'vacuumdb'],
                       "languages": LANGUAGES}

    ppg_14_versions.update({"deb_pkg_ver": fill_package_versions(packages=packages,
                                                                 distros=distros)})
    return ppg_14_versions


def get_pg15_versions(distros, packages, distro_type):
    ppg_15_versions = {
                       "deb_packages": fill_template_form(DEB12_PACKAGES_TEMPLATE, "15"),
                       "deb_provides": fill_provides_template_form(DEB_PROVIDES_TEMPLATE, "15"),
                       "rpm7_provides": fill_provides_template_form(RPM7_PROVIDES_TEMPLATE, "15"),
                       'rpm_provides': fill_provides_template_form(RPM_PROVIDES_TEMPLATE, "15"),
                       "rpm_packages": fill_template_form(RPM_PG13PACKAGES_TEMPLATE, "15"),
                       "rpm7_packages": fill_template_form(RPM7_PG13PACKAGES_TEMPLATE, "15"),
                       "rhel_files": fill_template_form(RHEL_FILES_TEMPLATE, "15"),
                       "deb_files": fill_template_form(DEB_FILES_TEMPLATE, "15"),
                       "extensions": get_extensions(distro_type),
                       "binaries": ['clusterdb', 'createdb', 'createuser',
                                    'dropdb', 'dropuser', 'pg_basebackup',
                                    'pg_config', 'pg_dump', 'pg_dumpall',
                                    'pg_isready', 'pg_receivewal', 'pg_recvlogical',
                                    'pg_restore', 'pg_verifybackup', 'psql',
                                    'reindexdb', 'vacuumdb'],
                       "languages": LANGUAGES}

    ppg_15_versions.update({"deb_pkg_ver": fill_package_versions(packages=packages,
                                                                 distros=distros)})
    return ppg_15_versions


def get_pg16_versions(distros, packages, distro_type):
    ppg_16_versions = {
                       "deb_packages": fill_template_form(DEB12_PACKAGES_TEMPLATE, "16"),
                       "deb_provides": fill_provides_template_form(DEB_PROVIDES_TEMPLATE, "16"),
                       "rpm7_provides": fill_provides_template_form(RPM7_PROVIDES_TEMPLATE, "16"),
                       'rpm_provides': fill_provides_template_form(RPM_PROVIDES_TEMPLATE, "16"),
                       "rpm_packages": fill_template_form(RPM_PG13PACKAGES_TEMPLATE, "16"),
                       "rpm7_packages": fill_template_form(RPM7_PG13PACKAGES_TEMPLATE, "16"),
                       "rhel_files": fill_template_form(RHEL_FILES_TEMPLATE, "16"),
                       "deb_files": fill_template_form(DEB_FILES_TEMPLATE, "16"),
                       "extensions": get_extensions(distro_type),
                       "binaries": ['clusterdb', 'createdb', 'createuser',
                                    'dropdb', 'dropuser', 'pg_basebackup',
                                    'pg_config', 'pg_dump', 'pg_dumpall',
                                    'pg_isready', 'pg_receivewal', 'pg_recvlogical',
                                    'pg_restore', 'pg_verifybackup', 'psql',
                                    'reindexdb', 'vacuumdb'],
                       "languages": LANGUAGES}

    ppg_16_versions.update({"deb_pkg_ver": fill_package_versions(packages=packages,
                                                                 distros=distros)})
    return ppg_16_versions


def get_pg17_versions(distros, packages, distro_type):
    ppg_17_versions = {
                       "deb_packages": fill_template_form(DEB12_PACKAGES_TEMPLATE, "17"),
                       "deb_provides": fill_provides_template_form(DEB_PROVIDES_TEMPLATE, "17"),
                       "rpm7_provides": fill_provides_template_form(RPM7_PROVIDES_TEMPLATE, "17"),
                       'rpm_provides': fill_provides_template_form(RPM_PROVIDES_TEMPLATE, "17"),
                       "rpm_packages": fill_template_form(RPM_PG13PACKAGES_TEMPLATE, "17"),
                       "rpm7_packages": fill_template_form(RPM7_PG13PACKAGES_TEMPLATE, "17"),
                       "rhel_files": fill_template_form(RHEL_FILES_TEMPLATE, "17"),
                       "deb_files": fill_template_form(DEB_FILES_TEMPLATE, "17"),
                       "extensions": get_extensions(distro_type),
                       "binaries": ['clusterdb', 'createdb', 'createuser',
                                    'dropdb', 'dropuser', 'pg_basebackup',
                                    'pg_config', 'pg_dump', 'pg_dumpall',
                                    'pg_isready', 'pg_receivewal', 'pg_recvlogical',
                                    'pg_restore', 'pg_verifybackup', 'psql',
                                    'reindexdb', 'vacuumdb'],
                       "languages": LANGUAGES}

    ppg_17_versions.update({"deb_pkg_ver": fill_package_versions(packages=packages,
                                                                 distros=distros)})
    return ppg_17_versions


def get_pg18_versions(distros, packages, distro_type):
    ppg_18_versions = {
                       "deb_packages": fill_template_form(DEB12_PACKAGES_TEMPLATE, "18"),
                       "deb_provides": fill_provides_template_form(DEB_PROVIDES_TEMPLATE, "18"),
                       "rpm7_provides": fill_provides_template_form(RPM7_PROVIDES_TEMPLATE, "18"),
                       'rpm_provides': fill_provides_template_form(RPM_PROVIDES_TEMPLATE, "18"),
                       "rpm_packages": fill_template_form(RPM_PG13PACKAGES_TEMPLATE, "18"),
                       "rpm7_packages": fill_template_form(RPM7_PG13PACKAGES_TEMPLATE, "18"),
                       "rhel_files": fill_template_form(RHEL_FILES_TEMPLATE, "18"),
                       "deb_files": fill_template_form(DEB_FILES_TEMPLATE, "18"),
                       "extensions": get_extensions(distro_type),
                       "binaries": ['clusterdb', 'createdb', 'createuser',
                                    'dropdb', 'dropuser', 'pg_basebackup',
                                    'pg_config', 'pg_dump', 'pg_dumpall',
                                    'pg_isready', 'pg_receivewal', 'pg_recvlogical',
                                    'pg_restore', 'pg_verifybackup', 'psql',
                                    'reindexdb', 'vacuumdb'],
                       "languages": LANGUAGES}

    ppg_18_versions.update({"deb_pkg_ver": fill_package_versions(packages=packages,
                                                                 distros=distros)})
    return ppg_18_versions


def get_ppg_versions(distro_type):
    """Get dictionary with versions
    :param distro_type: deb or rpm
    :return:
    """

    return {"ppg-14.0": get_pg14_versions(packages=["2:14.0-1", "1:226-1", '226-0'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-14.1": get_pg14_versions(packages=["2:14.1-1", "1:230-1", '230-0'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-14.2": get_pg14_versions(packages=["2:14.2-3", "1:237-2", '237-2'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-14.3": get_pg14_versions(packages=["2:14.3-3", "1:241-3", '241-3'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-14.4": get_pg14_versions(packages=["2:14.4-3", "1:241-4", '241-4'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-14.5": get_pg14_versions(packages=["2:14.5-3", "1:241-5", '241-5'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-14.6": get_pg14_versions(packages=["2:14.6-1", "1:241-6", '241-6'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-14.7": get_pg14_versions(packages=["2:14.7-1", "1:247-1", '247-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-14.8": get_pg14_versions(packages=["2:14.8-1", "1:250-1", '250-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-14.9": get_pg14_versions(packages=["2:14.9-1", "1:252-1", '252-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-14.10": get_pg14_versions(packages=["2:14.10-1", "1:256-1", '256-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-14.11": get_pg14_versions(packages=["2:14.11-1", "1:256-1", '256-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-14.12": get_pg14_versions(packages=["2:14.12-1", "1:259-1", '259-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-14.13": get_pg14_versions(packages=["2:14.13-1", "1:261-1", '261-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-14.15": get_pg14_versions(packages=["2:14.15-1", "1:266-1", '266-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-14.17": get_pg14_versions(packages=["2:14.17-1", "1:267-1", '267-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-15.0": get_pg15_versions(packages=["2:15.0-1", "1:241-5", '241-5'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-15.1": get_pg15_versions(packages=["2:15.1-1", "1:241-6", '241-6'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-15.2": get_pg15_versions(packages=["2:15.2-2", "1:247-1", '247-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-15.3": get_pg15_versions(packages=["2:15.3-1", "1:250-1", '250-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-15.4": get_pg15_versions(packages=["2:15.4-1", "1:252-1", '252-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-15.5": get_pg15_versions(packages=["2:15.5-1", "1:256-1", '256-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-15.6": get_pg15_versions(packages=["2:15.6-1", "1:256-1", '256-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-15.7": get_pg15_versions(packages=["2:15.7-1", "1:259-1", '259-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-15.8": get_pg15_versions(packages=["2:15.8-1", "1:261-1", '261-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-15.10": get_pg15_versions(packages=["2:15.10-1", "1:266-1", '266-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-15.12": get_pg15_versions(packages=["2:15.12-1", "1:267-1", '267-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-16.0": get_pg16_versions(packages=["2:16.0-1", "1:253-1", '253-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-16.1": get_pg16_versions(packages=["2:16.1-2", "1:256-1", '256-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-16.2": get_pg16_versions(packages=["2:16.2-1", "1:256-1", '256-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-16.3": get_pg16_versions(packages=["2:16.3-1", "1:259-1", '259-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-16.4": get_pg16_versions(packages=["2:16.4-1", "1:261-1", '261-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-16.6": get_pg16_versions(packages=["2:16.6-1", "1:266-1", '266-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-16.8": get_pg16_versions(packages=["2:16.8-1", "1:267-1", '267-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-17.0": get_pg17_versions(packages=["2:17.0-1", "1:264-1", '264-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-17.2": get_pg17_versions(packages=["2:17.2-1", "1:266-1", '266-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-17.4": get_pg17_versions(packages=["2:17.4-1", "1:267-1", '267-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-14.18": get_pg14_versions(packages=["2:14.18-1", "1:280-1", '280-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-15.13": get_pg15_versions(packages=["2:15.13-1", "1:280-1", '280-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-16.9": get_pg16_versions(packages=["2:16.9-1", "1:280-1", '280-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-17.5": get_pg17_versions(packages=["2:17.5-3", "1:277-1", '277-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-14.19": get_pg14_versions(packages=["2:14.19-1", "1:280-1", '280-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-15.14": get_pg15_versions(packages=["2:15.14-1", "1:280-1", '280-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-16.10": get_pg16_versions(packages=["2:16.10-1", "1:280-1", '280-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-17.6": get_pg17_versions(packages=["2:17.6-1", "1:280-1", '280-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-14.20": get_pg14_versions(packages=["2:14.20-2", "1:287-1", '287-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-15.15": get_pg15_versions(packages=["2:15.15-2", "1:287-1", '287-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-16.11": get_pg16_versions(packages=["2:16.11-2", "1:287-1", '287-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-17.7": get_pg17_versions(packages=["2:17.7-2", "1:287-1", '287-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-18.1": get_pg18_versions(packages=["3:18.1-3", "1:287-1", '287-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-14.22": get_pg14_versions(packages=["2:14.22-1", "1:289-1", '289-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-15.17": get_pg15_versions(packages=["2:15.17-1", "1:289-1", '289-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-16.13": get_pg16_versions(packages=["2:16.13-1", "1:289-1", '289-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-17.9": get_pg17_versions(packages=["2:17.9-1", "1:289-1", '289-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-18.3": get_pg18_versions(packages=["3:18.3-1", "1:289-1", '289-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-14.23": get_pg14_versions(packages=["2:14.23-1", "1:290-1", '290-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-15.18": get_pg15_versions(packages=["2:15.18-1", "1:290-1", '290-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-16.14": get_pg16_versions(packages=["2:16.14-1", "1:290-1", '290-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-17.10": get_pg17_versions(packages=["2:17.10-2", "1:290-1", '290-1'],
                                          distros=DISTROS, distro_type=distro_type),
            "ppg-18.4": get_pg18_versions(packages=["3:18.4-2", "1:290-2", '290-1'],
                                          distros=DISTROS, distro_type=distro_type),
            }
