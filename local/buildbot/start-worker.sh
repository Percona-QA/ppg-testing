#!/bin/sh
# one worker process per slot: buildbot runs at most one build per
# (builder, worker) pair, so parallelism needs several workers, not max_builds.
# names must match MOLECULE_WORKERS in master.cfg, hence the shared
# PPG_LOCAL_SLOTS.
set -e

# without it every molecule create fails deep in libvirt, fail here instead
: "${PPG_HYPERVISOR_SSH:?set PPG_HYPERVISOR_SSH, see local/README.md}"

# compose stages the hypervisor key at /run/ppg-ssh-key. If the host path did
# not exist, docker created a directory there instead -- catch that here, and
# install a real key with the 600 perms ssh demands.
if [ ! -f /run/ppg-ssh-key ]; then
    echo "error: /run/ppg-ssh-key is not a regular file." >&2
    echo "PPG_SSH_KEY (default ~/.ssh/ppg-buildbot) does not exist on the host:" >&2
    echo "docker auto-created a directory at that path -- remove it and point" >&2
    echo "PPG_SSH_KEY at a key authorized on the hypervisor, or run task bot-setup" >&2
    exit 1
fi
mkdir -p /root/.ssh
install -m 600 /run/ppg-ssh-key /root/.ssh/id_ed25519

SLOTS=${PPG_LOCAL_SLOTS:-4}
PASS=${PPG_WORKER_PASS:-ppg-local}

# the state volume outlives the container but the pid namespace does not:
# any twistd.pid in it is stale, and a sibling process can even reuse the
# recorded pid, making twistd refuse to start ("Another twistd server is
# running"). Nothing can be running yet this early in the entrypoint.
rm -f /bbw/molecule-*/twistd.pid

i=1
while [ "$i" -le "$SLOTS" ]; do
    d=/bbw/molecule-$i
    mkdir -p "$d"
    [ -f "$d/buildbot.tac" ] \
        || buildbot-worker create-worker "$d" master:9989 "molecule-$i" "$PASS"
    i=$((i + 1))
done

# all but the last daemonize; the last keeps the container alive
i=1
while [ "$i" -lt "$SLOTS" ]; do
    buildbot-worker start "/bbw/molecule-$i"
    i=$((i + 1))
done
exec buildbot-worker start --nodaemon "/bbw/molecule-$SLOTS"
