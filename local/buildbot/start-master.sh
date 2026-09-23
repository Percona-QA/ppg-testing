#!/bin/sh
# master.cfg imports tools/ and calls gen_groups.ensure(), which writes the
# generated ppg groups -- so it needs a writable tree, while /repo is mounted
# read-only on purpose. work on a copy; restart the master to pick up
# descriptor changes.
set -e

WORK=${PPG_TESTING_DIR:-/work}
mkdir -p /bb "$WORK"
rsync -a --delete --exclude .git/ --filter=':- .gitignore' /repo/ "$WORK"/

[ -f /bb/buildbot.tac ] || buildbot create-master -r /bb
ln -sf /cfg/master.cfg /bb/master.cfg
buildbot upgrade-master /bb
# stale pidfile from the previous container run, same story as the workers
rm -f /bb/twistd.pid
exec buildbot start --nodaemon /bb
