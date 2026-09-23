# Local buildbot for ppg-testing

A two-container buildbot that runs the molecule groups on the local/remote libvirt hypervisor.
Nothing here is generated or duplicated: `master.cfg` imports `tools/render.py` and builds the whole UI (one force scheduler per group, forms from the `params:` blocks) straight from the `scenario.yml` descriptors.

## Quick start

You need docker and a libvirt hypervisor, either this machine or a remote one reachable over ssh (see `local/README.md` for the hypervisor side).

```
task bot-setup
task bot-up
```

`bot-setup` is the one time host side part, and safe to rerun:
it copies `.env.example` to `local/buildbot/.env`, creates the hypervisor ssh key if there is none, authorizes it on the hypervisor with `ssh-copy-id` (this is where it may ask for your password), and checks that `virsh list` works over it.
For a remote hypervisor export `PPG_HYPERVISOR_SSH=user@host` before running it, or put it in `.env` first.
Without it the hypervisor is assumed to be this machine, and the worker sshes back to it as you through docker's `host.docker.internal` alias -- which means sshd has to be running here.

`bot-up` builds and starts the two containers, UI on http://localhost:8010/, no auth (bind it to localhost only).

## Settings

Compose reads `local/buildbot/.env` on its own (gitignored, per machine), variables exported in the shell that runs `task bot-up` win over it.
`.env.example` lists the ones worth touching:

```
PPG_HYPERVISOR_SSH=user@hypervisor-host
# optional, but useful
PPG_TESTING_BRANCH=main
# Changing the SSH key path is optional, but the key itself isn't
PPG_SSH_KEY=~/.ssh/ppg-buildbot
```

Builds clone the local `PPG_TESTING_BRANCH` and run `tools/run.py` from it, they don't use the local checkout.
This means that work doesn't have to be pushed to a remote to be available for them, but it has to be committed.

Everything compose reads:

| var | default | meaning |
| --- | --- | --- |
| `PPG_HYPERVISOR_SSH` | `<you>@host.docker.internal` | user@host of the hypervisor, the default is this machine via docker's host alias |
| `PPG_SSH_KEY` | `~/.ssh/ppg-buildbot` | private key for the hypervisor, staged into the worker with 600 perms. Must exist **on the machine running docker** and be authorized for the `PPG_HYPERVISOR_SSH` user -- a key that only exists inside a dev container does not count. If the path is missing at first `up`, docker leaves an empty root owned *directory* behind at it, which also breaks plain ssh; the worker refuses to start in that case, and `bot-setup` removes it |
| `PPG_LOCAL_SLOTS` | 4 | how many scenarios run in parallel |
| `PPG_TESTING_BRANCH` | `main` | default value of the TESTING_BRANCH form field, wins over the descriptor default |
| `PPG_WORKER_PASS` | `ppg-local` | worker password, only matters if you expose the ports |
| `PPG_BUILDBOT_URL` | `http://localhost:8010/` | base url the UI builds links with |

### Hypervisor ssh key

The worker talks to the hypervisor over ssh from inside the container, with no agent and nobody to type a passphrase.
It needs a key file on the machine running docker, without a passphrase, authorized for the `PPG_HYPERVISOR_SSH` user.
`bot-setup` does exactly this, by hand it is:

```
ssh-keygen -t ed25519 -N '' -f ~/.ssh/ppg-buildbot -C ppg-buildbot
ssh-copy-id -i ~/.ssh/ppg-buildbot.pub user@hypervisor-host
ssh -i ~/.ssh/ppg-buildbot user@hypervisor-host virsh -c qemu:///system list
```

If the last command lists the domains (or nothing, on an empty hypervisor) without asking for anything, the key works.
`~/.ssh/ppg-buildbot` is the default, a different path goes into `.env` as `PPG_SSH_KEY`; the worker stages it with 600 perms at start.
Host keys are accepted on first connect inside the container (`StrictHostKeyChecking accept-new`), nothing else needs to be copied in.

## Using it

The waterfall/grid stays empty until something is forced.
Every group has its own force scheduler named `run-<group>` (slashes to dashes, e.g. `run-pg_tde-tde`):

* **OS** -- multi select, defaults to the group's full os list
* **sequence** -- the sequences declared in the descriptor (`test`, `destroy`, ...)
* **TESTING_BRANCH** -- branch to check out
* one field per descriptor param: choice, boolean or string with the descriptor default. `PLATFORM` and `DESTROY_ENV` are never exposed, `PLATFORM` comes from the selected OS

The OS choices are the descriptor's full list, but entries the local libvirt backend cannot serve, like `rhel-*` (no subscription locally, use rocky instead) and `*-arm` are deselected by default. 
`local/env.sh` leaves those image keys unset, so explicitly picking one gets you a failure in molecule create, not a skip.

Forcing starts one `group-run` build on the master-local coordinator, which fans out to one `molecule-run` build per selected OS.
Those builds report under the virtual builder name `<group> <os>`, so a partially failing group shows up as per-OS red/green instead of one red blob.
Each of them is a single `tools/run.py --group ... --os <one>` call.

Capacity is `PPG_LOCAL_SLOTS` worker processes in the worker container.
The coordinator builds are in-process on the master and only wait, so several groups can be in flight at once.

## Sweeps

Two extra force schedulers run many groups from one button, on the `sweep-run` builder.
They fan out the same way, one `molecule-run` build per (group, os), tagged `sweep`, so the grid still shows per-OS red/green.

**release-sweep** -- what to run for a release candidate:

* **groups** -- multi select over every group, defaults to `ppg/pg-*`, `ppg/psp-*`, `pg_tde/*`, `pg_stat_monitor/*` and `psp/*`
* **sequence** -- defaults to `test`
* **VERSION**, **FROM_VERSION**, **REPO** -- set once for every selected group. Empty means "keep whatever the descriptor defaults to", and each group only gets the ones its `scenario.yml` actually declares, so it is safe to select groups with different param sets
* **TESTING_BRANCH**

Mind the scale: the default selection is 37 groups over their locally runnable os lists, about 450 molecule builds.
At 4 slots that is not a quick check -- trim the group selection unless you really mean the whole matrix for a local run.

Sweep currently only works safely with `PPG_LOCAL_SLOTS=1`: the libvirt backend has no base-volume locking yet, different groups on the *same* OS at the same time, all wanting the same base image, the second one can get a half-uploaded base.
Multiple slots can have sporadic failures for now.

`VERSION` and `FROM_VERSION` only reach the groups whose descriptor declares them, today `pg_tde/tde`, `pg_tde/auxiliary`, `pg_stat_monitor/*` and `psp/server_tests` for `VERSION` and nothing at all for `FROM_VERSION`.
The generated `ppg/*` groups declare no params yet, so a sweep cannot set their version; that descriptor gap is being closed separately.

A group that does not declare the requested sequence runs `test` instead, which every descriptor has -- better than dropping it from the sweep unnoticed.
`destroy` and `cleanup` are exempt from that fallback: those groups are skipped, because running a full test suite in place of a cleanup is expensive and not what was asked.
Skips are never silent: the sweep build lists them in a `skipped` log, goes orange when it dropped some groups, and fails outright when it dropped all of them, so an empty sweep cannot read as a clean one.

**destroy-sweep** -- mop up guests a crashed or cancelled run left behind. Same group select, `sequence` fixed to `destroy` (a `FixedParameter`, so it cannot silently become a test run), no version fields -- guest names do not depend on them. One extra field:

* **BUILD_NUMBER** -- which build's guests to remove, digits only. Empty means this build's own, which is a no-op; to clean up after build 41 of a group, put `41` here. Guest names embed the build number (`name_pattern` `{build}`), so molecule only ever destroys the ones matching it

Trim the group selection before you press it: `BUILD_NUMBER` applies to *every* selected group, and build numbers are per (group, os) builder, so the same number exists for unrelated groups.
A destroy sweep over the whole default selection with `BUILD_NUMBER=41` will happily remove the guests of a *running* build 41 of some group you did not mean to touch.
Select the groups you actually want cleaned.

Cancelling a build in the UI is normally enough on its own: the molecule step gets a SIGTERM first, and `tools/run.py` destroys its guests on the way out.

## Artifacts

Artifacts (molecule.log, report.xml, summary.json) land in the `artifacts` volume, one directory per fan out (the `group-run` or `sweep-run` build number, not the per-os one):

```
/artifacts/<group-slug>/<buildnumber>/<os>/
/artifacts/<group-slug>/sweep-<buildnumber>/<os>/
```

```
docker compose -f local/buildbot/docker-compose.yml exec worker ls -R /artifacts
```
