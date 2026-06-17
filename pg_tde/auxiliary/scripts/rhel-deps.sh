#!/bin/bash

set -e

# OpenBao (pre-built binary — no Go required)
# tar.gz arch uses Linux uname convention (x86_64 / arm64)
OPENBAO_VERSION=2.5.4
ARCH_TAR=$(uname -m | sed 's/aarch64/arm64/')
wget -q "https://github.com/openbao/openbao/releases/download/v${OPENBAO_VERSION}/bao_${OPENBAO_VERSION}_Linux_${ARCH_TAR}.tar.gz" -O /tmp/openbao.tar.gz
# Install to /usr/bin — /usr/local/bin is not in the minimal PATH inherited by
# meson test subprocesses on RHEL.
sudo tar -xzf /tmp/openbao.tar.gz -C /usr/bin bao
sudo chmod 0755 /usr/bin/bao
rm -f /tmp/openbao.tar.gz

# Cosmian KMS (native .rpm — no Docker required)
# RPM dir path uses amd64/arm64; RPM filename uses x86_64/aarch64 (RPM convention)
COSMIAN_VERSION=5.21.0
ARCH_DIR=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
ARCH_RPM=$(uname -m)
wget -q "https://package.cosmian.com/kms/${COSMIAN_VERSION}/rpm/${ARCH_DIR}/non-fips/static/cosmian-kms-server-non-fips-static-openssl_${COSMIAN_VERSION}_${ARCH_RPM}.rpm" -O /tmp/cosmian_kms.rpm
sudo rpm -ivh /tmp/cosmian_kms.rpm || true
sudo chmod 0755 /usr/sbin/cosmian_kms || true
sudo chmod 0755 /usr/local/cosmian/lib/ossl-modules/legacy.so 2>/dev/null || true
sudo chmod 0755 /usr/local/cosmian/lib/ossl-modules/ 2>/dev/null || true
rm -f /tmp/cosmian_kms.rpm
