#!/bin/bash
set -e

CERTS=/opt/cosmian/certs
DATA=/opt/cosmian/data

# Generate certs on first start (volume-mounted so they persist on the host).
# On docker restart the volume already has the certs; skip generation.
if [ ! -f "$CERTS/ca.pem" ]; then
    CERT_OUTPUT_DIR="$CERTS" /gen_certs.sh
fi

mkdir -p "$DATA"

cat > /opt/cosmian/kms.toml <<'EOF'
default_username = "admin"

[db]
database_type = "sqlite"
sqlite_path = "/opt/cosmian/data/db"
clear_database = true

[tls]
tls_p12_file         = "/opt/cosmian/certs/server.p12"
tls_p12_password     = "test"
clients_ca_cert_file = "/opt/cosmian/certs/ca.pem"

[socket_server]
socket_server_start    = true
socket_server_port     = 5556
socket_server_hostname = "0.0.0.0"

[http]
port     = 9998
hostname = "0.0.0.0"

[logging]
rust_log = "info,cosmian_kms=info"
EOF

export OPENSSL_MODULES=/usr/local/cosmian/lib/ossl-modules
exec cosmian_kms -c /opt/cosmian/kms.toml
