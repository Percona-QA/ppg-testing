# Local molecule runs on libvirt

Run any ppg-testing molecule scenario on a local or remote kvm/libvirt machine instead of AWS.

## Hypervisor host setup

The machine that runs the VMs needs:

* libvirt and qemu/kvm installed
* a user in the `libvirt` group, reachable over ssh with key auth
* an active `default` NAT network and a `default` dir storage pool

The pool commands also work remotely over qemu+ssh as an unprivileged libvirt-group user.

## Runner setup

The runner is where molecule runs.
It can be the hypervisor host itself, or any machine/container with ssh access to it.
It needs the virsh client, an openssh client and one of genisoimage, mkisofs or xorriso.

Use a python venv with molecule 3.3.0 for CI parity.
With go-task installed you can install it simply with:

```
task venv
task check
```

* `venv` creates `.venv` in the repo root (override with `PPG_VENV`)
* `check` verifies virsh, the iso tool and the libvirt network and pool.

## Quick start

On a machine that is both hypervisor and runner:

```
cd ppg-testing
task tde OS=debian-13 -- --param TDE_BRANCH=release-2.2
```

The `TDE_BRANCH` override is needed because the descriptor default `release-2.2.0` is a stale upstream ref, the branch is `release-2.2`.

## Remote hypervisor

Export `PPG_HYPERVISOR_SSH` before running molecule:

```
export PPG_HYPERVISOR_SSH=user@host
task check # optional, verifies connection
```

## Scenario params

The scenarios need the same vars CI passes.
They are declared in each group's `scenario.yml` under `params:` with the defaults the jenkins job would use, `tools/run.py` exports them for molecule and `--param NAME=VALUE` overrides one.
`task list GROUP=pg_tde/tde` prints the params with their defaults.
An exported env var of the same name loses against the declared default, so use `--param`.

## Env var reference

| var | default | meaning |
| --- | --- | --- |
| driver | delegated (from PPG_LOCAL_DRIVER) | backend selection, "default" for molecule >=6 |
| BUILD_NUMBER | local | instance-name suffix. static on purpose, so destroy-by-name works from any shell; override for parallel runs of the same scenario |
| LIBVIRT_URI | qemu:///system | libvirt connection |
| LIBVIRT_POOL | default | storage pool |
| LIBVIRT_NETWORK | default | NAT network |
| PPG_HYPERVISOR_SSH | unset | user@host of a remote hypervisor, derives LIBVIRT_URI and ProxyJump |
| PPG_LOCAL_CPUS | from instance_type | override the instance_type to size mapping |
| PPG_LOCAL_MEMORY | from instance_type | same, memory in MiB |
| PPG_IMAGE_CACHE | .cache/images in the repo root | downloaded vendor images |

## Not supported locally

* RHEL -- no subscription, use rocky
* arm64 -- planned later

## task shortcuts

`Taskfile.yml` at the repo root is optional sugar over `tools/run.py`, every task just shells out, so `tools/run.py` works fine standalone without go-task installed.
Each task sources `local/env.sh` itself, so you only need to export `PPG_HYPERVISOR_SSH` (if remote) before calling `task`.

Install go-task if you don't have it:

```
sh -c "$(curl -sL https://taskfile.dev/install.sh)" -- -d -b ~/.local/bin
```

```
task venv                                   # create the molecule venv
task check                                  # runner tools + libvirt connection
task list                                   # list groups
task list GROUP=pg_tde/tde                  # group's oses, sequences and params
task tde OS=ol-9                            # family shortcut, runs molecule test
task pgsm OS=ol-9
task psp OS=ol-9
task ppg SCENARIO=pg-17 OS=ol-9
task run GROUP=pg_tde/tde OS="ol-9 debian-12" -- --param TDE_BRANCH=main --keep
task tde OS=ol-9 SEQ=converge               # any sequence the descriptor declares
task destroy GROUP=pg_tde/tde OS=ol-9
```

`OS` can list several scenarios, space separated, run sequentially; `--fail-fast` after `--` stops at the first failure.
`SEQ` is the sequence name from `scenario.yml` (default `test`), anything after `--` is passed straight through to run.py.
`rhel-*` and `*-arm` are listed but not supported locally, see above.

`tools/run.py` renders the group's `molecule/<os>/molecule.yml` files from `scenario.yml` first (they are not in git, `tools/render.py` does it, `--clean` removes them), runs the sequence, always destroys the guests afterwards unless `--keep` is given, and collects `molecule.log`, `report.xml` and a `summary.json` per run under `local/runs/`.
