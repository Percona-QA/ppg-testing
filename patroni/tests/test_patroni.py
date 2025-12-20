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


# def test_cluster_status(host):
#     cluster_cmd = 'patronictl -c /var/lib/pgsql/patroni_test/postgresql1.yml list -f json'
#     cluster_result = host.run(cluster_cmd)
#     print(cluster_result.stdout)
#     assert cluster_result.rc == 0, cluster_result.stderr
#     cluster_json = json.loads(cluster_result.stdout)
#     assert len(cluster_json) == 3, f"Must have 3 nodes in the cluster, but found {len(cluster_json)}"
#     assert cluster_json[0]['State'] == 'running', cluster_json[0]
#     assert cluster_json[1]['State'] == 'streaming', cluster_json[1]
#     assert cluster_json[2]['State'] == 'streaming', cluster_json[2]
#     # for cluster in cluster_json:
#     #     assert cluster['State'] == 'running', cluster


def test_cluster_status1(host):
    """
    Tests that the cluster status shows exactly 3 nodes and asserts that
    every node's State is either 'running' or 'streaming'.
    Prints the state of all nodes to the console on failure.
    """
    cluster_cmd = 'patronictl -c /var/lib/pgsql/patroni_test/postgresql1.yml list -f json'

    # 1. Execute the command
    cluster_result = host.run(cluster_cmd)

    # Print the raw JSON output for context/debugging
    print("\n--- patronictl list JSON Output ---")
    print(cluster_result.stdout)
    print("------------------------------------\n")

    # 2. Check command execution success
    assert cluster_result.rc == 0, f"patronictl command failed with RC {cluster_result.rc}: {cluster_result.stderr}"

    try:
        cluster_json = json.loads(cluster_result.stdout)
    except json.JSONDecodeError as e:
        pytest.fail(f"Failed to parse JSON output: {e}\nOutput: {cluster_result.stdout}")

    # 3. Check node count
    expected_nodes = 3
    assert len(cluster_json) == expected_nodes, f"Must have {expected_nodes} nodes in the cluster, but found {len(cluster_json)}"

    # 4. Assert State and Print to Console on Failure

    # Define acceptable states
    acceptable_states = {'running', 'streaming'}

    # List to collect failures for better reporting
    failed_nodes = []

    print("--- Patroni Node States ---")
    for node in cluster_json:
        node_name = node.get('Member', 'Unknown')
        node_state = node.get('State', 'N/A')

        print(f"Node: {node_name}, Role: {node.get('Role', 'N/A')}, State: {node_state}")

        if node_state not in acceptable_states:
            failed_nodes.append(node)

    print("---------------------------\n")

    # Final assertion: Check if any nodes failed the state check
    if failed_nodes:
        # If there are failures, construct a detailed failure message and use pytest.fail
        fail_message = (
            "One or more nodes are not in an expected state ('running' or 'streaming').\n"
            "Failed Nodes:\n"
        )
        for node in failed_nodes:
            fail_message += f" - Node: {node.get('Member')}, State: {node.get('State')}, Full details: {node}\n"

        pytest.fail(fail_message)

    print("✅ All node states are either 'running' (primary) or 'streaming' (replicas).")


def test_cluster_status2(host):
    cluster_cmd = "patronictl -c /var/lib/pgsql/patroni_test/postgresql1.yml list -f json"
    result = host.run(cluster_cmd)

    # Print raw output for debugging
    print("patronictl output:")
    print(result.stdout)

    assert result.rc == 0, f"Command failed: {result.stderr}"

    cluster = json.loads(result.stdout)

    # Ensure cluster size
    assert len(cluster) == 3, (
        f"Expected 3 nodes in cluster, found {len(cluster)}: {cluster}"
    )

    allowed_states = {"running", "streaming"}

    for idx, node in enumerate(cluster):
        node_name = node.get("Member", f"node-{idx}")
        node_state = node.get("State")

        # Print node state to console
        print(f"Node {idx} ({node_name}) state: {node_state}")

        assert node_state in allowed_states, (
            f"Node {node_name} has invalid state '{node_state}', "
            f"expected one of {allowed_states}"
        )

def test_haproxy_web(host):
    curl_cmd = 'curl http://localhost:7000'
    curl_result = host.run(curl_cmd)
    assert curl_result.rc == 0, curl_result.stderr
