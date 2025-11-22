import os
import json

import testinfra.utils.ansible_runner


testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def test_etcd(host):
    assert host.service("etcd").is_running


def test_patroni_config_file_exists(host):
    f = host.file("/var/lib/pgsql/patroni_test/postgresql1.yml")
    assert f.exists
    assert f.user == "postgres"
    assert f.group == "postgres"
    assert f.mode == 0o644


def test_patroni_service(host):
    assert host.service("patroni").is_running, print(host.run("systemctl status patroni").stdout)
    assert host.service("patroni1").is_running, print(host.run("systemctl status patroni1").stdout)
    assert host.service("patroni2").is_running, print(host.run("systemctl status patroni2").stdout)


def test_haproxy_connect(host):
    select = 'cd && psql --host localhost --port 5000 postgres -U postgres -c "select version()"'
    result = host.run(select)
    print(result.stdout)
    assert result.rc == 0, result.stderr


def test_cluster_status(host):
    cluster_cmd = 'patronictl -c /var/lib/pgsql/patroni_test/postgresql1.yml list -f json'
    cluster_result = host.run(cluster_cmd)
    print(cluster_result.stdout)
    assert cluster_result.rc == 0, cluster_result.stderr
    cluster_json = json.loads(cluster_result.stdout)
    assert len(cluster_json) == 3, f"Must have 3 nodes in the cluster, but found {len(cluster_json)}"
    assert cluster_json[0]['State'] == 'running', cluster_json[0]
    assert cluster_json[1]['State'] == 'streaming', cluster_json[1]
    assert cluster_json[2]['State'] == 'streaming', cluster_json[2]
    # for cluster in cluster_json:
    #     assert cluster['State'] == 'running', cluster


def test_haproxy_web(host):
    curl_cmd = 'curl http://localhost:7000'
    curl_result = host.run(curl_cmd)
    assert curl_result.rc == 0, curl_result.stderr
