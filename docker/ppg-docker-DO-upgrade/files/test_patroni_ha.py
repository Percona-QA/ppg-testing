import os
import subprocess
import textwrap
import time

import psycopg2
import pytest
import requests

# --- Configuration constants/settings ---
MAJOR_VER = os.getenv("VERSION").split(".")[0]
MAJOR_MINOR_VER = os.getenv("VERSION")
DOCKER_REPO = os.getenv("DOCKER_REPOSITORY")
IMG_TAG = os.getenv("TAG")
IMAGE = f"{DOCKER_REPO}/percona-distribution-postgresql-custom:{IMG_TAG}"
PG_BIN_DIR = f"/usr/pgsql-{MAJOR_VER}/bin"
NETWORK_NAME = "patroni_test_net"
ETCD_NAME = "etcd_node"


def get_patroni_status(port):
    """Helper to query the Patroni REST API."""
    try:
        response = requests.get(f"http://localhost:{port}/patroni", timeout=2)
        if response.status_code == 200:
            return response.json()
    except Exception:
        pass
    return None


def wait_for_leader(nodes, timeout=90):
    """Polls until a leader exists and is running."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        for node in nodes.values():
            status = get_patroni_status(node["port"])
            if status:
                role = status.get("role")
                state = status.get("state")
                # Handle both modern 'primary' and legacy 'master/leader' terms
                if role in ["primary", "master", "leader"] and state == "running":
                    return node
        time.sleep(3)
    return None


@pytest.fixture(scope="session", autouse=True)
def docker_env():
    """Ensure a clean network environment."""
    subprocess.run(["docker", "network", "rm", NETWORK_NAME], capture_output=True)
    subprocess.run(["docker", "network", "create", NETWORK_NAME], check=True)
    yield
    subprocess.run(["docker", "network", "rm", NETWORK_NAME], capture_output=True)


@pytest.fixture(scope="session")
def etcd(docker_env):
    """Start etcd as the Distributed Configuration Store (Architecture-Agnostic)."""
    subprocess.run(["docker", "rm", "-f", ETCD_NAME], capture_output=True)

    # REMOVE '--platform', 'linux/amd64' to allow native execution
    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            ETCD_NAME,
            "--network",
            NETWORK_NAME,
            "quay.io/coreos/etcd:v3.5.0",
            "/usr/local/bin/etcd",
            "--advertise-client-urls",
            f"http://{ETCD_NAME}:2379",
            "--listen-client-urls",
            "http://0.0.0.0:2379",
        ],
        check=True,
    )

    # Increase the sleep slightly for ARM runners which might be slower to initialize
    time.sleep(5)
    yield ETCD_NAME
    subprocess.run(["docker", "rm", "-f", ETCD_NAME], capture_output=True)


@pytest.fixture(scope="session")
def cluster(etcd):
    """Initialize a 2-node Patroni cluster."""
    nodes = {
        "node1": {"name": "pg-node-1", "port": 18008, "pg_port": 19008},
        "node2": {"name": "pg-node-2", "port": 18009, "pg_port": 19009},
    }

    for node in nodes.values():
        name = node["name"]
        api_port = node["port"]
        pg_port = node["pg_port"]
        data_dir = f"/tmp/pdata_{name}"
        conf_path = f"/tmp/patroni_{name}.yaml"

        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        if os.path.exists(conf_path):
            os.remove(conf_path)

        config_content = textwrap.dedent(f"""
            scope: test-cluster
            name: {name}
            etcd3:
              hosts: ["{ETCD_NAME}:2379"]
            restapi:
              listen: "0.0.0.0:8008"
              connect_address: "{name}:8008"
            bootstrap:
              dcs:
                ttl: 30
                loop_wait: 10
                retry_timeout: 10
                postgresql:
                  parameters:
                    synchronous_commit: "on"
                    synchronous_standby_names: "*"
                    max_wal_senders: 10
                    max_replication_slots: 10
                    wal_level: replica
              method: initdb
              initdb: [auth-host: md5, auth-local: trust, encoding: UTF8, data-checksums]
              pg_hba:
                - host replication replicator 0.0.0.0/0 md5
                - host all all 0.0.0.0/0 md5
            postgresql:
              listen: "0.0.0.0:5432"
              connect_address: "{name}:5432"
              data_dir: "{data_dir}"
              bin_dir: "{PG_BIN_DIR}"
              authentication:
                superuser: {{username: postgres, password: password}}
                replication: {{username: replicator, password: password}}
        """)

        with open(conf_path, "w") as f:
            f.write(config_content)

        subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                name,
                "--hostname",
                name,
                "--network",
                NETWORK_NAME,
                "--shm-size=256m",
                "-v",
                f"{conf_path}:/etc/patroni.yaml:ro",
                "--entrypoint",
                "/usr/bin/patroni",
                "--user",
                "postgres",
                "-e",
                "PYTHONUNBUFFERED=1",
                "-e",
                "POSTGRES_PASSWORD=password",
                "-p",
                f"{api_port}:8008",
                "-p",
                f"{pg_port}:5432",
                IMAGE,
                "/etc/patroni.yaml",
            ],
            check=True,
        )

        subprocess.run(
            [
                "docker",
                "exec",
                "--user",
                "root",
                name,
                "sh",
                "-c",
                f"mkdir -p {data_dir} && chown -R postgres:postgres {data_dir}"
                f" && chmod 700 {data_dir}",
            ],
            check=True,
        )

    print("\n[...] Waiting for cluster election...")
    leader = wait_for_leader(nodes, timeout=90)

    if not leader:
        res = subprocess.run(["docker", "logs", "pg-node-1"], capture_output=True, text=True)
        print(f"\n--- LOGS FROM PG-NODE-1 ---\n{res.stdout}")
        pytest.fail("Cluster failed to elect a leader.")

    yield nodes
    for node in nodes.values():
        subprocess.run(["docker", "rm", "-f", node["name"]], capture_output=True)


# --- Tests ---
def test_failover_and_data_persistence(cluster):
    """Verify leader discovery, write data, kill leader, and check standby promotion."""

    # 1. Identify roles and WAIT for standby to be ready
    initial_leader = None
    standby = None

    # Give the cluster 30 seconds to reach a steady state where both nodes are 'running'
    timeout = time.time() + 60
    while time.time() < timeout:
        states = {n["name"]: get_patroni_status(n["port"]) for n in cluster.values()}

        # Check if we have one leader and one running standby
        leader_node = next(
            (
                n
                for n in cluster.values()
                if states[n["name"]]
                and states[n["name"]].get("role") in ["primary", "master", "leader"]
            ),
            None,
        )
        standby_node = next((n for n in cluster.values() if n != leader_node), None)

        if (
            leader_node
            and states[standby_node["name"]]
            and states[standby_node["name"]].get("state") == "running"
        ):
            initial_leader = leader_node
            standby = standby_node
            break
        time.sleep(2)

    assert initial_leader is not None, "Cluster did not reach a healthy 'running' state in time"
    print(f"\n[✓] Cluster synced. Leader: {initial_leader['name']}, Standby: {standby['name']}")

    # 2. Write data to leader
    conn = psycopg2.connect(
        host="localhost", port=initial_leader["pg_port"], user="postgres", password="password"
    )
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("CREATE TABLE failover_test (id int, val text);")
        cur.execute("INSERT INTO failover_test VALUES (1, 'patroni-ha-test');")
        # CRITICAL: Force flush to ensure WAL is generated and sent
        cur.execute("CHECKPOINT;")
    conn.close()

    # 3. Small sleep to ensure WAL replication finishes
    print("[...] Waiting for WAL streaming...")
    time.sleep(3)

    # 4. Terminate leader
    print(f"[!] Stopping leader: {initial_leader['name']}")
    subprocess.run(["docker", "stop", initial_leader["name"]], check=True)

    # 5. Wait for standby to promote
    print(f"[...] Waiting for {standby['name']} to promote...")
    new_leader = wait_for_leader({"standby": standby}, timeout=60)

    assert new_leader is not None, "Standby failed to promote"
    print(f"[✓] New leader: {new_leader['name']}")

    # 6. Verify data
    conn = psycopg2.connect(
        host="localhost", port=new_leader["pg_port"], user="postgres", password="password"
    )
    with conn.cursor() as cur:
        # Retry logic here is also helpful if the DB is still in 'recovery' mode for a split second
        cur.execute("SELECT val FROM failover_test WHERE id = 1;")
        row = cur.fetchone()
        assert row is not None
        assert row[0] == "patroni-ha-test"
    conn.close()
