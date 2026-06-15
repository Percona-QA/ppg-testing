#!/bin/bash
set -e
DIR=/opt/cosmian_certs
mkdir -p "$DIR"

# CA
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$DIR/ca.key" -out "$DIR/ca.pem" \
  -subj '/CN=pg_tde-test-ca'

# Server CSR + signed cert (mirrors CosmianKms::gen_certs)
openssl req -newkey rsa:2048 -nodes \
  -keyout "$DIR/server.key" -out "$DIR/server.csr" \
  -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1'
openssl x509 -req -in "$DIR/server.csr" \
  -CA "$DIR/ca.pem" -CAkey "$DIR/ca.key" -CAcreateserial \
  -days 1 -out "$DIR/server.pem" -copy_extensions copy

# Server PKCS#12 bundle
openssl pkcs12 -export \
  -out "$DIR/server.p12" -inkey "$DIR/server.key" -in "$DIR/server.pem" \
  -password pass:test

# Client CSR + signed cert
openssl req -newkey rsa:2048 -nodes \
  -keyout "$DIR/client.key" -out "$DIR/client.csr" \
  -subj '/CN=pg_tde-client'
openssl x509 -req -in "$DIR/client.csr" \
  -CA "$DIR/ca.pem" -CAkey "$DIR/ca.key" -CAcreateserial \
  -days 1 -out "$DIR/client.pem"
