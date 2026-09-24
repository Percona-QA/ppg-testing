# ppg-testing

Molecule scenarios for the Percona PostgreSQL products: the PPG distribution, pg_tde, pg_stat_monitor, psp and the bundled extensions and tools.

CI runs them on AWS through [jenkins-pipelines](https://github.com/Percona-Lab/jenkins-pipelines), the same scenarios are runnable on a local libvirt hypervisor.

## Layout

* one directory per product (`pg_tde/`, `pg_stat_monitor/`, `pgbackrest/`, ...), one group per subdirectory.
* every group has a `scenario.yml` descriptor: os list, sequences, jenkins params and their defaults.
  The `molecule.yml` files are not in git, `tools/render.py` renders them from the descriptor.
* `ppg/` -- the versioned server/upgrade/ha groups (`pg-14`..`pg-18`, `psp-16`) are generated from `ppg/versions.yml` and `templates/groups/` by `tools/gen_groups.py`, also not in git.
* `catalog/` -- os lists and AWS settings shared by all descriptors.
* `playbooks/`, `tasks/`, `files/` -- ansible shared between the groups.
* `tools/` -- render, run, generate; `tools/tests/` are their unit tests (`pytest tools/tests`).

## Running locally

Locally, on kvm/libvirt: [local/README.md](local/README.md).
With go-task installed `task --list` shows the shortcuts, `task tde OS=debian-13` runs a group.

A web UI over the same runner, one force scheduler per group and release sweeps: [local/buildbot/README.md](local/buildbot/README.md).
