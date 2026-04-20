#!/bin/sh

set -e

if [ -d "../certs/opensearch" ]; then
    SSL_DIR="../certs/opensearch"
else
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    SSL_DIR="${SCRIPT_DIR}/../certs/opensearch"
fi

CERT_VALIDITY_DAYS=3650

mkdir -p "${SSL_DIR}"
cd "${SSL_DIR}"

echo "==> Step 1: Generating Root CA private key..."
openssl genrsa -out root-ca-key.pem 2048

echo "==> Step 2: Generating Root CA certificate..."
openssl req -new -x509 -sha256 -key root-ca-key.pem -out root-ca.pem \
    -days ${CERT_VALIDITY_DAYS} \
    -subj "/C=ID/ST=EastJava/L=Surabaya/O=MATAELANG/OU=CSRG/CN=mataelang-ca"

echo "==> Step 3: Generating OpenSearch Node private key..."
openssl genrsa -out opensearch-node1-key.pem 2048

echo "==> Step 4: Generating Certificate Signing Request..."
openssl req -new -key opensearch-node1-key.pem \
    -out opensearch-node1.csr \
    -config opensearch-node.cnf

echo "==> Step 5: Signing certificate with Root CA..."
openssl x509 -req -in opensearch-node1.csr \
    -CA root-ca.pem \
    -CAkey root-ca-key.pem \
    -CAcreateserial \
    -out opensearch-node1.pem \
    -days ${CERT_VALIDITY_DAYS} \
    -sha256 \
    -extensions v3_req \
    -extfile opensearch-node.cnf

echo "==> Step 6: Setting proper permissions..."
chmod 644 root-ca.pem opensearch-node1.pem opensearch-node1-key.pem root-ca-key.pem

openssl x509 -in opensearch-node1.pem -text -noout | grep -A 10 "Subject Alternative Name"