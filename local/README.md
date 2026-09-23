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
export VERSION=ppg-18.4 REPO=testing IO_METHOD=sync
export TDE_REPO=https://github.com/percona/pg_tde.git TDE_BRANCH=release-2.2
task tde OS=debian-13
```

## Remote hypervisor

Export `PPG_HYPERVISOR_SSH` before running molecule:

```
export PPG_HYPERVISOR_SSH=user@host
task check # optional, verifies connection
```

## Scenario env vars

The scenarios themselves need the same vars CI passes, check the matching job in the jenkins-pipelines repo for the specific component.

For example for pg_tde/tde:

```
export VERSION=ppg-18.4
export REPO=testing
export TDE_REPO=https://github.com/percona/pg_tde.git
export TDE_BRANCH=release-2.2
export IO_METHOD=sync
```

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

Install go-task if you don't have it:

```
sh -c "$(curl -sL https://taskfile.dev/install.sh)" -- -d -b ~/.local/bin
```

```
task venv                                   # create the molecule venv
task check                                  # runner tools + libvirt connection
task list                                   # list groups
task list GROUP=pg_tde/tde                  # group's scenarios runnable locally
task tde OS=ol-9                            # family shortcut, runs molecule test
task pgsm OS=ol-9
task psp OS=ol-9
task ppg SCENARIO=pg-17 OS=ol-9
task run GROUP=pg_tde/tde OS="ol-9 debian-12" -- --destroy=never
task tde OS=ol-9 SEQ=converge               # any molecule subcommand
task destroy GROUP=pg_tde/tde OS=ol-9
```

`OS` can list several scenarios, space separated, run sequentially; the first failure stops the loop.
`SEQ` is the molecule subcommand (default `test`), anything after `--` is passed straight through to molecule.
`task list GROUP=...` hides the `-arm` and `rhel-*` scenarios since those are not supported locally.

The `molecule/<os>/molecule.yml` files are not in git. `task run` renders them from the group's `scenario.yml` with `tools/render.py` before calling molecule, the same way the jenkins jobs do. `python tools/render.py --group pg_tde/tde` does it by hand, `--clean` removes the output again.
