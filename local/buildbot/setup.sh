#!/bin/sh
# host side, one time: .env from .env.example, hypervisor ssh key created and
# authorized. Safe to rerun, every step is skipped when already done.
set -e
cd "$(dirname "$0")"

envval() {
    # last assignment wins, like compose. only used for keys the shell does
    # not set, so the precedence matches what compose will see at up time
    [ -f .env ] && sed -n "s/^$1=//p" .env | tail -1
}

if [ ! -f .env ]; then
    cp .env.example .env
    echo "created .env from .env.example"
fi

target=${PPG_HYPERVISOR_SSH:-$(envval PPG_HYPERVISOR_SSH)}
if [ -z "$target" ]; then
    # same default as docker-compose.yml, written out so .env says what it does
    target="${USER:-$(id -un)}@host.docker.internal"
    echo "PPG_HYPERVISOR_SSH=$target" >> .env
    echo "no hypervisor given, using this machine: PPG_HYPERVISOR_SSH=$target"
fi

# host.docker.internal only resolves inside the containers, from here it is
# localhost. sshd has to be running on this machine for that to work at all.
case $target in
    *@host.docker.internal) copy_target="${target%@*}@localhost" ;;
    *) copy_target=$target ;;
esac

key=${PPG_SSH_KEY:-$(envval PPG_SSH_KEY)}
key=${key:-~/.ssh/ppg-buildbot}
case $key in
    "~/"*) key="$HOME/${key#\~/}" ;;
esac

# a bind mount whose host path is missing makes docker create an empty root
# owned directory there. That was the old key default, and it breaks every
# ssh here (default identities are tried too). rmdir only needs write perms
# on the parent, so no root needed; a non-empty one is not ours to remove.
for stale in "$key" "$HOME/.ssh/id_ed25519"; do
    if [ -d "$stale" ]; then
        if rmdir "$stale" 2>/dev/null; then
            echo "removed empty directory $stale (left behind by docker)"
        else
            echo "$stale is a directory, not a key file. Remove it first" >&2
            exit 1
        fi
    fi
done

if [ -f "$key" ]; then
    echo "key $key exists, keeping it"
else
    mkdir -p "$(dirname "$key")"
    ssh-keygen -t ed25519 -N '' -f "$key" -C ppg-buildbot
    echo "created $key"
fi

check() {
    ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -i "$key" "$copy_target" \
        virsh -c qemu:///system list >/dev/null 2>&1
}

if check; then
    echo "$copy_target already accepts $key"
else
    echo "authorizing $key on $copy_target (may ask for your password)"
    if ! ssh-copy-id -i "$key.pub" "$copy_target"; then
        echo "ssh-copy-id to $copy_target failed. It needs sshd there, and a password or an already authorized key to log in with" >&2
        exit 1
    fi
    if ! check; then
        echo "key is installed but 'virsh -c qemu:///system list' fails over ssh as $copy_target." >&2
        echo "check libvirt access for that user, see local/README.md" >&2
        exit 1
    fi
fi

echo "done. next: task bot-up"
