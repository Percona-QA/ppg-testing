import json
import os

import pytest
import testinfra.utils.ansible_runner


testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')

# postgis/setup/tasks/main.yml already asserts a handful of quick, deterministic
# spatial checks (ST_Distance, ST_Contains, address_standardizer, topology,
# tiger_geocoder) inline during converge, as a fast fail-fast smoke layer.
# This suite is the deeper functional layer: it targets each of the C
# libraries PostGIS links against (GEOS, PROJ, GDAL, SFCGAL, json-c, and
# protobuf-c) individually, so a packaging regression that silently drops
# support for one of them (a common failure mode - e.g. building without
# --with-sfcgal, or against a GDAL without a given driver) shows up as a
# specific, attributable failure instead of a generic "some query broke".


def _psql(host, sql, dbname="postgres"):
    with host.sudo("postgres"):
        result = host.run(
            "psql -tA -d {} -c \"{}\"".format(dbname, sql.replace('"', '\\"'))
        )
    assert result.rc == 0, result.stderr
    return result.stdout.strip()


def test_postgis_full_version_reports_expected_libraries(host):
    """
    postgis_full_version() is the single source of truth for which
    geometry/raster/topology libraries a given build was actually compiled
    against. This is the cheapest possible check that catches a build
    silently losing SFCGAL, JSON-C, GDAL, etc. support - the functional
    tests below only prove the *specific function* they call still works,
    not that every library is linked in general.
    """
    version_string = _psql(host, "SELECT postgis_full_version();")
    for token in (
        "GEOS", "PROJ", "GDAL", "SFCGAL", "LIBXML", "LIBJSON", "LIBPROTOBUF",
        "TOPOLOGY", "RASTER",
    ):
        assert token in version_string, (
            "postgis_full_version() is missing expected token '{}': {}".format(
                token, version_string
            )
        )


# ---------------------------------------------------------------------------
# GEOS (core 2D geometry operations)
# ---------------------------------------------------------------------------

def test_geos_buffer_produces_a_valid_geometry(host):
    area = _psql(
        host,
        "SELECT ST_Area(ST_Buffer(ST_GeomFromText('POINT(0 0)'), 10, 'quad_segs=100'));",
    )
    # A radius-10 circle has area pi*r^2 ~= 314.159; quad_segs=100 keeps the
    # polygon approximation of the circle tight enough to compare within 1%.
    assert float(area) == pytest.approx(314.159, rel=0.01), area

    is_valid = _psql(
        host,
        "SELECT ST_IsValid(ST_Buffer(ST_GeomFromText('POINT(0 0)'), 10));",
    )
    assert is_valid == "t", is_valid


def test_geos_intersection_and_union(host):
    intersection_area = _psql(
        host,
        "SELECT ST_Area(ST_Intersection("
        "ST_GeomFromText('POLYGON((0 0,0 10,10 10,10 0,0 0))'),"
        "ST_GeomFromText('POLYGON((5 5,5 15,15 15,15 5,5 5))')));",
    )
    assert float(intersection_area) == pytest.approx(25.0), intersection_area

    union_area = _psql(
        host,
        "SELECT ST_Area(ST_Union("
        "ST_GeomFromText('POLYGON((0 0,0 10,10 10,10 0,0 0))'),"
        "ST_GeomFromText('POLYGON((5 5,5 15,15 15,15 5,5 5))')));",
    )
    # 100 + 100 - 25 (overlap) = 175
    assert float(union_area) == pytest.approx(175.0), union_area


def test_geos_convex_hull(host):
    hull_area = _psql(
        host,
        "SELECT ST_Area(ST_ConvexHull(ST_GeomFromText("
        "'MULTIPOINT(0 0, 10 0, 10 10, 0 10, 5 5)')));",
    )
    # The interior point (5,5) must not affect the hull of the surrounding square.
    assert float(hull_area) == pytest.approx(100.0), hull_area


# ---------------------------------------------------------------------------
# PROJ (coordinate reference system transforms)
# ---------------------------------------------------------------------------

def test_proj_transforms_between_srids(host):
    result = _psql(
        host,
        "SELECT ST_AsText(ST_Transform("
        "ST_SetSRID(ST_MakePoint(-73.9857, 40.7484), 4326), 3857));",
    )
    assert result.startswith("POINT("), result
    x_str, y_str = result[len("POINT("):-1].split(" ")
    # Web Mercator (EPSG:3857) coords for Times Square, NYC, computed from the
    # closed-form spherical Pseudo-Mercator formula (R=6378137m) that defines
    # EPSG:3857 - not an approximation, so a tight tolerance is safe and a
    # broken/no-op PROJ transform (identity passthrough) would be obviously wrong.
    assert float(x_str) == pytest.approx(-8236050.45, abs=10), result
    assert float(y_str) == pytest.approx(4975301.25, abs=10), result


# ---------------------------------------------------------------------------
# GDAL (raster import/export)
# ---------------------------------------------------------------------------

def test_gdal_raster_export(host):
    gdal_version = _psql(host, "SELECT postgis_gdal_version();")
    assert gdal_version, "postgis_gdal_version() returned no output"

    png_size = _psql(
        host,
        "SELECT octet_length(ST_AsPNG(ST_AddBand("
        "ST_MakeEmptyRaster(4, 4, 0, 0, 1), 1, '8BUI', 100, 0)));",
    )
    assert int(png_size) > 0, png_size


# ---------------------------------------------------------------------------
# SFCGAL (3D / solid geometry operations)
# ---------------------------------------------------------------------------

def test_sfcgal_3d_solid_operations(host):
    sfcgal_version = _psql(host, "SELECT postgis_sfcgal_version();")
    assert sfcgal_version, "postgis_sfcgal_version() returned no output"

    # Extrude a flat 4x4 square by height 3 into a 4x4x3 box.
    # Surface area of a box = 2*(l*w + l*h + w*h) = 2*(16 + 12 + 12) = 80.
    # Using a rectangular prism (no curves) keeps this exact across SFCGAL
    # versions - no floating-point tessellation noise to account for.
    surface_area = _psql(
        host,
        "SELECT ST_3DArea(ST_Extrude(ST_MakePolygon(ST_MakeLine(ARRAY["
        "ST_MakePoint(0,0), ST_MakePoint(4,0), ST_MakePoint(4,4),"
        "ST_MakePoint(0,4), ST_MakePoint(0,0)])), 0, 0, 3));",
    )
    assert float(surface_area) == pytest.approx(80.0), surface_area


# ---------------------------------------------------------------------------
# json-c (GeoJSON encode/decode)
# ---------------------------------------------------------------------------

def test_json_c_geojson_roundtrip(host):
    geojson_text = _psql(
        host, "SELECT ST_AsGeoJSON(ST_SetSRID(ST_MakePoint(1, 2), 4326));"
    )
    parsed = json.loads(geojson_text)
    assert parsed["type"] == "Point", parsed
    assert parsed["coordinates"] == pytest.approx([1, 2]), parsed

    # Round-trip back through ST_GeomFromGeoJSON to exercise the decode path too.
    roundtrip_wkt = _psql(
        host,
        "SELECT ST_AsText(ST_GeomFromGeoJSON('{}'));".format(
            geojson_text.replace("'", "''")
        ),
    )
    assert roundtrip_wkt.startswith("POINT("), roundtrip_wkt
    rt_x, rt_y = roundtrip_wkt[len("POINT("):-1].split(" ")
    assert float(rt_x) == pytest.approx(1.0), roundtrip_wkt
    assert float(rt_y) == pytest.approx(2.0), roundtrip_wkt


# ---------------------------------------------------------------------------
# protobuf-c (Mapbox Vector Tile encoding) - bonus coverage: postgis_full_version()
# reports LIBPROTOBUF, so it's part of "all functional aspects" even though
# it wasn't named explicitly.
# ---------------------------------------------------------------------------

def test_protobuf_c_mvt_encoding(host):
    mvt_size = _psql(
        host,
        "SELECT octet_length(ST_AsMVT(t)) FROM ("
        "SELECT 1 AS id, ST_AsMVTGeom("
        "ST_GeomFromText('POINT(1 1)'),"
        "ST_MakeBox2D(ST_MakePoint(0,0), ST_MakePoint(10,10))"
        ") AS geom) AS t;",
    )
    assert int(mvt_size) > 0, mvt_size


# ---------------------------------------------------------------------------
# Migrated from postgis/setup/tasks/main.yml, where these ran as inline
# Ansible `assert` tasks during converge. Moved here so all functional
# assertions live in one place instead of being split across YAML and Python.
# ---------------------------------------------------------------------------

def test_geos_basic_distance_contains_validity(host):
    distance = _psql(
        host,
        "SELECT ST_Distance(ST_GeomFromText('POINT(0 0)'), ST_GeomFromText('POINT(3 4)'));",
    )
    assert float(distance) == pytest.approx(5.0), distance

    contains = _psql(
        host,
        "SELECT ST_Contains(ST_GeomFromText('POLYGON((0 0,0 10,10 10,10 0,0 0))'), ST_GeomFromText('POINT(5 5)'));",
    )
    assert contains == "t", contains

    is_valid = _psql(
        host,
        "SELECT ST_IsValid(ST_GeomFromText('POLYGON((0 0,0 10,10 10,10 0,0 0))'));",
    )
    assert is_valid == "t", is_valid


def test_gdal_raster_width_from_makeemptyraster(host):
    width = _psql(host, "SELECT ST_Width(ST_MakeEmptyRaster(10, 20, 0, 0, 1));")
    assert int(width) == 10, width


def test_fuzzystrmatch_levenshtein(host):
    distance = _psql(host, "SELECT levenshtein('GUMBO', 'GAMBOL');")
    assert int(distance) == 2, distance


def test_address_standardizer_parse_address(host):
    """
    The original Ansible version of this check asserted on a column named
    `house_num`, which doesn't exist - parse_address()'s composite return
    type names it `num` (columns are: num, street, street2, address1, city,
    state, zip, zipplus, country). That's what actually failed in CI
    ("column \"house_num\" does not exist"); fixed here during the migration.
    """
    house_num = _psql(
        host,
        "SELECT num FROM parse_address('1 Devonshire Place PH301, Boston, MA 02109');",
    )
    assert house_num == "1", house_num


def test_postgis_topology_create_topology(host):
    topology_id = _psql(
        host, "SELECT topology.CreateTopology('ppg_test_topo', 4326);"
    )
    assert int(topology_id) > 0, topology_id


def test_tiger_geocoder_normalize_address(host):
    result = _psql(
        host,
        "SELECT (na).address FROM normalize_address('1 Devonshire Place, Boston, MA 02109') AS na;",
    )
    assert result, "normalize_address returned no output"
