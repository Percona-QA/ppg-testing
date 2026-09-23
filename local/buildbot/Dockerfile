FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        git openssh-client libvirt-clients genisoimage rsync \
    && rm -rf /var/lib/apt/lists/*

# versions match the proven local venv (ppg-molecule): molecule 3.3.0 pins
# click<8/pluggy<1/PyYAML<6, so pytest and friends have to stay old too.
# the ansible bundle (not bare ansible-core) is needed for community.general,
# used by the setup roles (pam_limits, modprobe).
RUN pip install --no-cache-dir \
        "buildbot[bundle]==4.3.0" "buildbot-worker==4.3.0" \
        "molecule==3.3.0" "ansible==9.13.0" "ansible-lint==5.4.0" \
        "PyYAML==5.3.1" "pytest==7.4.4" "pytest-testinfra==10.2.2" \
        "Jinja2==3.1.6" "paramiko==2.12.0"

# the hypervisor and the guests are throwaway, host keys are noise
RUN mkdir -p /etc/ssh/ssh_config.d \
    && printf 'Host *\n  StrictHostKeyChecking accept-new\n' > /etc/ssh/ssh_config.d/local.conf

# the worker clones from the bind-mounted checkout, which is owned by the
# host user while git runs as root here -- exempt everything from the
# dubious-ownership check, this container only ever touches that one repo
RUN git config --system --add safe.directory "*"

COPY start-master.sh start-worker.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/start-master.sh /usr/local/bin/start-worker.sh
