import os
import json

import testinfra.utils.ansible_runner


testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def test_patroni(host):
    assert host.service("etcd").is_running
    assert host.service("patroni").is_running, print(host.run("systemctl status patroni").stdout)
    assert host.service("patroni1").is_running, print(host.run("systemctl status patroni1").stdout)
    assert host.service("patroni2").is_running, print(host.run("systemctl status patroni2").stdout)
    select = 'cd && psql --host localhost --port 5000 postgres -U postgres -c "select version()"'
    result = host.run(select)
    print(result.stdout)
    assert result.rc == 0, result.stderr

    state_cmd = 'patronictl -c /var/lib/pgsql/patroni_test/postgresql1.yml list -f json'
    state_result = host.run(state_cmd)
    print(state_cmd.stdout)
    assert state_result.rc == 0, result.stderr

    state_json = json.loads(state_cmd.stdout)
    assert state_json[0]['state'] == 'running', state_result[0]
    assert state_json[1]['state'] == 'running', state_result[1]
    assert state_json[2]['state'] == 'running', state_result[2]

    curl_cmd = 'curl http://localhost:7000'
    curl_result = host.run(curl_cmd)
    print(curl_cmd.stdout)
    assert curl_result.rc == 0, curl_result.stderr
