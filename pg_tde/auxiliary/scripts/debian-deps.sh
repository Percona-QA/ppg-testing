#!/bin/bash

DEPS=(
    # Setup
    wget
    # Build
    bison
    docbook-xml
    docbook-xsl
    flex
    gettext
    libicu-dev
    libkrb5-dev
    libldap2-dev
    liblz4-dev
    libpam0g-dev
    libperl-dev
    libreadline-dev
    libselinux1-dev
    libssl-dev
    libsystemd-dev
    libxml2-dev
    libxml2-utils
    libxslt1-dev
    libzstd-dev
    lz4
    mawk
    meson
    perl
    pkgconf
    python3-dev
    systemtap-sdt-dev
    tcl-dev
    uuid-dev
    xsltproc
    zlib1g-dev
    zstd
    # Build pg_tde
    libcurl4-openssl-dev
    # Test
    libipc-run-perl
    # Test pg_tde
    libhttp-server-simple-perl
)

sudo apt-get update
sudo apt-get install -y ${DEPS[@]}

bash -c "$(wget -O - https://apt.llvm.org/llvm.sh)"

# OpenBao (pre-built binary — no Go required)
OPENBAO_VERSION=2.5.4
ARCH=$(dpkg --print-architecture | sed 's/amd64/x86_64/')
wget -q "https://github.com/openbao/openbao/releases/download/v${OPENBAO_VERSION}/bao_${OPENBAO_VERSION}_Linux_${ARCH}.tar.gz" -O /tmp/openbao.tar.gz
sudo tar -xzf /tmp/openbao.tar.gz -C /usr/local/bin bao
sudo chmod 0755 /usr/local/bin/bao
rm -f /tmp/openbao.tar.gz

# Cosmian KMS (native .deb — no Docker required)
COSMIAN_VERSION=5.21.0
ARCH_DEB=$(dpkg --print-architecture)
wget -q "https://package.cosmian.com/kms/${COSMIAN_VERSION}/deb/${ARCH_DEB}/non-fips/static/cosmian-kms-server-non-fips-static-openssl_${COSMIAN_VERSION}_${ARCH_DEB}.deb" -O /tmp/cosmian_kms.deb
sudo dpkg -i /tmp/cosmian_kms.deb
sudo chmod 0755 /usr/sbin/cosmian_kms
sudo chmod 0755 /usr/local/cosmian/lib/ossl-modules/legacy.so 2>/dev/null || true
rm -f /tmp/cosmian_kms.deb