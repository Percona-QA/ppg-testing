# Release watcher: automatic QA for packages in testing

When the build team pushes PPG packages to a `testing` repository, the
packages are tested and the result goes to Slack, with no one starting a job.

* On success, the build team's channel gets "ready to be released".
* On failure, `#postgresql-test` gets the failing jobs with links.

Promoting to `release` stays with the build team.

```
repo.percona.com/ppg-18.x/.../testing
        │  every 15 min
        ▼
ppg-release-watcher (Jenkins, cron)
   tools/release_watch.py poll
   ├─ new, complete, settled? ── no ──► nothing (state commit only)
   └─ yes: VERSIONS.yml attempt=running, commit
        │
        ▼
ppg-release-qa (one per package set)
   runs the mapped jobs (ppg-multiOS-parallel, ppg-upgrade-parallel, ...)
   in waves, retrying each failed job once
   tools/release_watch.py record
   ├─ all green → verified := attempt → Slack: ready to release
   └─ any red  → verified unchanged  → Slack: what failed
```

| Piece | Where |
|---|---|
| Decision logic, repo parsing | `tools/release_watch.py` (ppg-testing) |
| What to watch and which jobs to run | `release_watch/config.yml` (ppg-testing) |
| Tests (`pytest tools/tests`) | `tools/tests/test_release_watch.py` |
| State: `VERSIONS.yml` | branch `release-watch-state` of ppg-testing |
| Jenkins jobs | `ppg/ppg-release-watcher.*`, `ppg/ppg-release-qa.*` (jenkins-pipelines) |
| Git and Python helpers for both jobs | `vars/ppgReleaseWatch.groovy` (jenkins-pipelines) |

## How a new package set is recognized

A *stream* is one product line, such as `ppg-18`. For each stream, the watcher:

1. **Finds the newest minor repo.** It scans upward from the last verified minor with cheap HEAD requests and picks the highest repo that exists. Gaps are expected (for example `ppg-18.3`, then `ppg-18.6`); the scan only stops after `minor_lookahead` (3) missing minors in a row. The previous existing minor is found the same way and is used as the upgrade source.
2. **Reads the package indexes.** It reads the apt `Packages` and yum `repodata/primary.xml` for every OS and arch in the config. It then normalizes versions, so `2:18.5-1.noble` and `18.5-1.el9` both become `18.5-1`. The build number (the `-1` / `-2`) is always kept; only the epoch and the distro tag are removed.
   * **Every component is tracked automatically.** With `track_sources: true`, the watcher records each *source package* it finds, which is what the pool directories are called (`percona-haproxy`, `percona-pg-cron`, `psycopg2`, …), as `deb:<name>` and `rpm:<name>`. All 23 PPG 18 components are covered without listing binary package names, and a component added to the distribution later is picked up with no config change.
   * **Third-party dependencies are tracked too, without blocking.** The rpm repos also ship dependencies (PostGIS's gdal, geos, proj, CGAL; Patroni's `python3.12-*`), whose builds legitimately differ between RHEL 8, 9 and 10. A bump still triggers QA, but only sources matching `strict_sources` (`percona-*`) must agree across platforms; differences in the others are listed as variants.
   * **When both builds are in the repo** (for example `2.8.23-1` and `2.8.23-2` after a re-release), the highest wins.
   * **Each stream only knows its own repos.** Components are discovered from what is in them, never from a fixed list, so `percona-pg-oidc-validator18` (PG 18 only) is simply not part of ppg-17, and `percona-pg-telemetry` (up to ppg-17) is not part of ppg-18. Neither is reported as missing.
3. **Compares with `verified`.** If nothing is newer, it stops. That's why daily rebuilds with the same version never start anything. A build-number bump of any component (`2.8.23-1` → `2.8.23-2`, or pgbadger `13.2-2` → `13.2-3` in a new minor) counts as newer and is tested. With `compare: upstream`, build bumps are ignored and only upstream versions count.
4. **Waits until the push is finished.** It launches only when all of these hold:
   * required packages are present on every platform;
   * all platforms of one family (deb or rpm) agree on the version;
   * every platform of the last verified set is present again;
   * every component of the last verified set is present again (it may not be pushed yet);
   * nothing has changed for `settle_minutes` (60). When only components changed and the server did not, the wait is `component_settle_minutes` (180) instead: on a re-release the rebuilt components can land before the new server build, and testing them against the old server would raise false failures. In a new minor repo the server is required, so nothing is tested before it arrives, however late.

   If a push stays partial for `incomplete_alert_hours`, it posts one warning.
5. **Refuses mis-pushed packages.** The server in `ppg-18.N` must be `18.N.x`, and no package may be older than the last verified build. Otherwise nothing is launched, and the qa and release channels are both told once what looks wrong. The build team pushes the right packages and QA starts by itself. An intended downgrade goes in `allow_downgrade`, or is accepted once with `FORCE_STREAMS`.
6. **Launches only the relevant jobs.** Each job has an `on:` list of package names or globs, matched against both the named packages (`server`) and the tracked components (`deb:percona-patroni`). A pgbadger-only rebuild, for example, runs the server BVT, not the upgrade suites. A server release runs everything.

## VERSIONS.yml and the rollback

`verified` holds the last versions that passed QA, per stream. That's the
VERSIONS file.

* A launch writes the candidate into `attempt` with `status: running`, and does not touch `verified`.
* A pass copies the attempt into `verified`.
* A failure leaves `verified` as it was. That is the rollback.

The failed attempt is kept with `status: failed`. Without that record, the next poll 15 minutes later would see "newer than verified" again. It would then re-launch the same broken packages forever, burning EC2 and flooding Slack.

The same package set is therefore never re-tested automatically. Any new build (a new version or release number) is tested. To re-run the same set, for example after an infrastructure failure, start the watcher with `RETRY_STREAMS=ppg-18`.

A run that never reports back is marked failed after `stale_run_hours`. `ppg-release-qa` itself times out at 16 hours and records an abort, so this is only a backstop.

Every state change is a commit on `release-watch-state`, which gives you a full audit trail of what was tested, when, and with which result.

## Rollout

1. **Merge both branches.** Merge ppg-testing first, since the jobs check out its `main`. Then create the two Jenkins jobs from the YAML definitions.
2. **Check write access.** Both jobs push with the Jenkins credential `GITHUB_API_TOKEN` over HTTPS. It's the same token other jobs use to push the VERSIONS file to `Percona-QA/package-testing`, and it's already used by `ppg/postgis_tarballs.groovy`. The token's GitHub user needs write access to `Percona-QA/ppg-testing`, and it only ever pushes to the `release-watch-state` branch. The token is sent as an HTTP header, never stored in the workspace's `.git/config`. If a job log shows `could not read Username for 'https://github.com'`, the token was rejected or lacks access to the repo.
3. **Set the release channel.** Set `slack.release` in `config.yml` to the build team's channel.
4. **Check coverage from a Jenkins agent.** From a ppg-testing checkout on an agent, run:
   ```
   python3 tools/release_watch.py --state /tmp/V.yml observe ppg-18
   ```
   Every Percona component of the release should appear as a `deb:` and an `rpm:` key, `complete` should be `true`, and `conflicts` should be empty. This also proves the agent can reach repo.percona.com.
5. **Record a baseline.** Run the watcher once by hand with `BASELINE=true`. Without this, the first poll would treat everything currently in testing as new and test all of it. This first run also activates the watcher's 15-minute schedule: Jenkins only registers a pipeline's own cron trigger after the job has run once. Re-baseline also after enabling `track_sources` on a stream whose state was recorded without it, since the component entries would otherwise all count as new.
6. **Watch in dry-run mode.** The job ships with `DRY_RUN` defaulting to `true`, so the cron only logs what it would launch. Leave it like that for a few days, and compare against what the build team announces.
7. **Go live.** Change the `DRY_RUN` default to `false` in `ppg-release-watcher.groovy` and tell the build team they no longer need to ping QA.

## Day-to-day

| Situation | Action |
|---|---|
| Packages failed QA, build team fixes them | Nothing. The new build is detected automatically |
| Failure was infrastructure (AWS, agent) | Watcher with `RETRY_STREAMS=ppg-18` |
| Test now without waiting for settle, or re-test unchanged packages | Watcher with `FORCE_STREAMS=ppg-18` |
| New major (ppg-19) | Add a stream line in `config.yml`, then run `BASELINE` with `STREAMS=ppg-19` if packages already exist |
| Add or change a job | Edit `jobs:` in the template; `{version}` etc. are filled per launch |
| See the current state | `python3 tools/release_watch.py --state VERSIONS.yml show` on a checkout of the state branch |
| A component was removed from a stream on purpose | Add it to `allow_removed` in `config.yml` (e.g. `"*pg-telemetry*"`), or run the watcher once with `FORCE_STREAMS`. The Slack result lists it as removed |
| A new component appears | Nothing: it counts as a change and is tested |
| Components landed, server build still coming | Nothing: component-only changes wait `component_settle_minutes` (3h) so the server joins the same run |

The watcher itself posts to `#postgresql-test` once when it starts failing,
for example when a repo is unreadable, and once when it recovers.

## Known limits

* **Duplicate Slack messages.** The downstream jobs still send their own Slack messages. Consider muting those when started by `ppg-release-qa` so only the summary appears.
* **Upgrade source versions.** `minor-upgrade` upgrades from `release`, starting at the last verified version of the stream; on a respin of that same version, it starts at the previous minor repo that exists (18.3 before 18.6, when 18.4 and 18.5 were never published). `major-upgrade` starts from the previous major's last verified version, taken from `testing` because it may not be released yet.
* **Disabled streams.** `psp-16` and the tarball stream are included but disabled until their names and URLs are confirmed with `observe`.
* **Dropped platforms.** If an OS is deliberately dropped from a new minor, the "platform missing" rule keeps the stream waiting and posts one warning. Re-baseline that stream.
