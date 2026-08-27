from tools import catalog


def test_arm_entry():
    e = catalog.os_entry("debian-13-arm")
    assert e["arm"] and e["base"] == "debian-13"
    assert e["ami_var"] == "debian13"


def test_lists_reference_known_os_keys():
    bases = {k[:-4] if k.endswith("-arm") else k for k in catalog.load("os-lists.yml")["all"]}
    assert bases == set(catalog.load("os.yml"))


def test_os_entry_fields_sane():
    for os_name, e in catalog.load("os.yml").items():
        assert e["family"] in ("deb", "rpm"), os_name
        assert e["aws"]["ssh_user"], os_name
        assert e["aws"]["root_device"], os_name
