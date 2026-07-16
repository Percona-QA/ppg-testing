import os
import json
import time
import pytest
import testinfra.utils.ansible_runner


testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def test_etcd(host):
    assert host.service("etcd").is_running


def test_patroni_service(host):
    assert host.service("patroni").is_running, print(host.run("systemctl status patroni").stdout)
    assert host.service("patroni1").is_running, print(host.run("systemctl status patroni1").stdout)
    assert host.service("patroni2").is_running, print(host.run("systemctl status patroni2").stdout)


def test_haproxy_connect(host):
    select = 'cd && psql --host localhost --port 5000 postgres -U postgres -c "select version()"'
    result = host.run(select)
    print(result.stdout)
    assert result.rc == 0, result.stderr


def test_patroni_config_file_exists(host):
    with host.sudo("postgres"):
        f = host.file("/var/lib/pgsql/patroni_test/postgresql1.yml")
        assert f.exists
        assert f.user == "postgres"
        assert f.group == "postgres"
        assert f.mode == 0o644


@pytest.fixture(scope="module")
def patroni_cluster_data(host):
    """
    Fixture to execute patronictl and return the parsed JSON data for the cluster.
    """
    with host.sudo("postgres"):
        cluster_cmd = "patronictl -c /var/lib/pgsql/patroni_test/postgresql1.yml list -f json"
        # Execute the command
        cluster_result = host.run(cluster_cmd)

        assert cluster_result.rc == 0, cluster_result.stderr

    # Print the raw JSON output for context/debugging
    print("\n--- patronictl list JSON Output ---")
    print(cluster_result.stdout)
    print("------------------------------------\n")

    # Check command execution success
    if cluster_result.rc != 0:
        pytest.fail(f"patronictl command failed with RC {cluster_result.rc}: {cluster_result.stderr}")

    # Check node count
    try:
        cluster_json = json.loads(cluster_result.stdout)
    except json.JSONDecodeError as e:
        pytest.fail(f"Failed to parse JSON output: {e}\nOutput: {cluster_result.stdout}")

    expected_nodes = 3
    if len(cluster_json) != expected_nodes:
        pytest.fail(f"Must have {expected_nodes} nodes in the cluster, but found {len(cluster_json)}")

    return cluster_json


def test_cluster_node_roles(patroni_cluster_data):
    """
    Tests that the cluster has exactly one 'Leader' and two 'Replica' nodes.
    """
    role_counts = {'Leader': 0, 'Replica': 0}

    # Iterate through all nodes and count their roles
    for node in patroni_cluster_data:
        role = node.get('Role')
        member = node.get('Member', 'Unknown')

        # Count roles if they are the ones we care about
        if role in role_counts:
            role_counts[role] += 1
        else:
            # Fail if we find an unexpected role like 'Initializing', 'Pending', etc.
            pytest.fail(f"Node '{member}' has an unexpected Role: '{role}'. Expected 'Leader' or 'Replica'.")

    # Assert the final counts
    fail_message = ""
    if role_counts['Leader'] != 1:
        fail_message += f"Expected 1 Leader, but found {role_counts['Leader']}.\n"

    if role_counts['Replica'] != 2:
        fail_message += f"Expected 2 Replicas, but found {role_counts['Replica']}.\n"

    if fail_message:
        # Print the counts to console before failing
        print(f"\n--- Node Role Counts ---\n{json.dumps(role_counts, indent=2)}\n------------------------")
        pytest.fail(f"Cluster role validation failed:\n{fail_message}")

    print("✅ Cluster has the correct role distribution (1 Leader, 2 Replicas).")


def test_role_state_mapping(patroni_cluster_data):
    """
    Tests that the 'Leader' node has State 'running' and 'Replica' nodes have State 'streaming'.
    """
    failed_nodes = []

    # Define the required role-state mapping
    expected_states = {
        'Leader': 'running',
        'Replica': 'streaming'
    }

    print("\n--- Patroni Role-State Check ---")
    for node in patroni_cluster_data:
        role = node.get('Role')
        state = node.get('State')
        member = node.get('Member', 'Unknown')

        print(f"Node: {member}, Role: {role}, State: {state}")

        # Check if the observed state matches the expected state for that role
        if role in expected_states and state != expected_states[role]:
            failed_nodes.append({
                'member': member,
                'role': role,
                'actual_state': state,
                'expected_state': expected_states[role]
            })

    print("--------------------------------")

    # Final assertion
    if failed_nodes:
        fail_message = (
            "One or more nodes failed the Role-State mapping check.\n"
            "Mismatched Nodes:\n"
        )
        for node in failed_nodes:
            fail_message += (
                f" - Node: {node['member']} (Role: {node['role']}) "
                f"Expected State: '{node['expected_state']}', Actual State: '{node['actual_state']}'\n"
            )

        pytest.fail(fail_message)

    print("✅ All nodes have the correct state based on their role (Leader=running, Replica=streaming).")


def test_cluster_status(patroni_cluster_data):
    """
    Tests that the cluster status shows exactly 3 nodes and asserts that
    every node's State is either 'running' or 'streaming'.
    Prints the state of all nodes to the console on failure.
    """
    # Check node count
    expected_nodes = 3
    assert len(patroni_cluster_data) == expected_nodes, f"Must have {expected_nodes} nodes in the cluster, but found {len(patroni_cluster_data)}"

    # Assert State and Print to Console on Failure

    # Define acceptable states
    acceptable_states = {'running', 'streaming'}

    # List to collect failures for better reporting
    failed_nodes = []

    print("--- Patroni Node States ---")
    for node in patroni_cluster_data:
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


# Patroni's Member name (the `name:` field in each node's postgresql*.yml) is
# not the same as the systemd unit that runs it - map one to the other so we
# know which service to stop to fail over a given member.
MEMBER_TO_SERVICE = {
    "postgresql0": "patroni",
    "postgresql1": "patroni1",
    "postgresql2": "patroni2",
}


def _patronictl_list(host):
    with host.sudo("postgres"):
        result = host.run(
            "patronictl -c /var/lib/pgsql/patroni_test/postgresql1.yml list -f json"
        )
        assert result.rc == 0, result.stderr
    return json.loads(result.stdout)


def test_patroni_failover(host, patroni_cluster_data):
    """
    Stops the current Patroni leader's service to simulate a crash, confirms
    a different member is elected Leader within a bounded timeout, then
    restarts the stopped service and confirms it rejoins as a healthy
    replica. This is the core behavior Patroni exists to provide, and was
    previously never exercised - every other test in this file only checks
    a static snapshot of an already-healthy cluster.
    """
    leader = next(n for n in patroni_cluster_data if n.get("Role") == "Leader")
    leader_member = leader["Member"]
    leader_service = MEMBER_TO_SERVICE[leader_member]

    print(f"\nStopping current leader '{leader_member}' (service {leader_service}) to trigger failover")
    stop_result = host.run(f"systemctl stop {leader_service}")
    assert stop_result.rc == 0, stop_result.stderr

    try:
        new_leader_member = None
        deadline = time.time() + 60
        while time.time() < deadline:
            cluster = _patronictl_list(host)
            leaders = [n for n in cluster if n.get("Role") == "Leader"]
            if len(leaders) == 1 and leaders[0]["Member"] != leader_member:
                new_leader_member = leaders[0]["Member"]
                break
            time.sleep(5)

        assert new_leader_member is not None, (
            f"No new leader was elected within 60s after stopping '{leader_member}'"
        )
        print(f"✅ New leader elected: {new_leader_member}")
    finally:
        print(f"Restarting {leader_service} so the old leader rejoins as a replica")
        restart_result = host.run(f"systemctl start {leader_service}")
        assert restart_result.rc == 0, restart_result.stderr

        deadline = time.time() + 60
        rejoined = False
        while time.time() < deadline:
            cluster = _patronictl_list(host)
            if len(cluster) == 3 and all(
                n.get("State") in ("running", "streaming") for n in cluster
            ):
                rejoined = True
                break
            time.sleep(5)
        assert rejoined, f"'{leader_member}' did not rejoin as a healthy member within 60s"
