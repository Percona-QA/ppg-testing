# source me before running molecule locally:
#   . local/env.sh
# For a remote hypervisor set PPG_HYPERVISOR_SSH=user@host first.

export driver=${PPG_LOCAL_DRIVER:-delegated}
export BUILD_NUMBER=${BUILD_NUMBER:-local}

if [ -n "${PPG_HYPERVISOR_SSH:-}" ]; then
    export LIBVIRT_URI="qemu+ssh://${PPG_HYPERVISOR_SSH}/system"
    export ANSIBLE_SSH_COMMON_ARGS="${ANSIBLE_SSH_COMMON_ARGS:+${ANSIBLE_SSH_COMMON_ARGS} }-o ProxyJump=${PPG_HYPERVISOR_SSH}"
else
    export LIBVIRT_URI=${LIBVIRT_URI:-qemu:///system}
fi

export ANSIBLE_HOST_KEY_CHECKING=False

# same variable names as jenkins-pipelines/vars/moleculeEnvPPG.groovy,
# values are keys into playbooks/libvirt/images.yml instead of AMI ids.
# rhel keys stay unset on purpose: no subscription locally, use rocky.
export ami_debian12_x86_64=debian-12
export ami_debian13_x86_64=debian-13
export ami_ol8_x86_64=ol-8
export ami_ol9_x86_64=ol-9
export ami_ol10_x86_64=ol-10
export ami_rocky8_x86_64=rocky-8
export ami_rocky9_x86_64=rocky-9
export ami_rocky10_x86_64=rocky-10
export ami_ubuntu22_x86_64=ubuntu-22
export ami_ubuntu24_x86_64=ubuntu-24
export ami_ubuntu26_x86_64=ubuntu-26
