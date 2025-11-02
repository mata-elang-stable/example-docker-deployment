#!/bin/bash

set -e
cd ..
source .env
cd certs

# ========================
# Create CA
# ========================
create_ca() {
    echo "Creating CA..."
    rm -f truststore.jks ca.srl ca.key ca.crt ca.pem
    openssl req -new -nodes \
        -x509 \
        -days 365 \
        -newkey rsa:2048 \
        -keyout ca.key \
        -out ca.crt \
        -config ca.cnf

    # PEM for client services
    cp ca.crt ca.pem

    # Java truststore for Kafka UI / Schema Registry
    keytool -import -alias mataelang-ca \
        -file ca.crt \
        -keystore truststore.jks \
        -storepass $SSL_PASSWORD -noprompt
}

# ========================
# Create Broker Credentials
# ========================
create_broker_creds() {
    local cert=$1
    echo "Creating broker credentials for $cert..."

    mkdir -p ${cert}-creds

    # Generate key + CSR
    openssl req -new \
        -newkey rsa:2048 \
        -keyout ${cert}-creds/${cert}.key \
        -out ${cert}-creds/${cert}.csr \
        -config ${cert}-creds/${cert}.cnf \
        -nodes

    # Sign CSR with CA
    openssl x509 -req \
        -days 3650 \
        -in ${cert}-creds/${cert}.csr \
        -CA ca.crt \
        -CAkey ca.key \
        -CAcreateserial \
        -out ${cert}-creds/${cert}.crt \
        -extfile ${cert}-creds/${cert}.cnf \
        -extensions v3_req

    # Export PKCS12 including only server cert + CA cert (chain)
    openssl pkcs12 -export \
        -in ${cert}-creds/${cert}.crt \
        -inkey ${cert}-creds/${cert}.key \
        -chain \
        -CAfile ca.crt \
        -name ${cert} \
        -out ${cert}-creds/${cert}.p12 \
        -password pass:$SSL_PASSWORD

    # Convert to PKCS12 keystore for broker usage
    keytool -importkeystore \
        -deststorepass $SSL_PASSWORD \
        -destkeystore ${cert}-creds/kafka.${cert}.keystore.pkcs12 \
        -srckeystore ${cert}-creds/${cert}.p12 \
        -deststoretype PKCS12 \
        -srcstoretype PKCS12 \
        -noprompt \
        -srcstorepass $SSL_PASSWORD

    # Save passwords
    echo $SSL_PASSWORD > ${cert}-creds/${cert}_sslkey_creds
    echo $SSL_PASSWORD > ${cert}-creds/${cert}_keystore_creds
}

# ========================
# Create Schema Registry Credentials
# ========================
create_schema_registry_creds() {
    local cert="schema-registry"
    echo "Creating Schema Registry credentials..."

    mkdir -p ${cert}-creds

    # Generate key + CSR
    openssl req -new \
        -newkey rsa:2048 \
        -keyout ${cert}-creds/${cert}.key \
        -out ${cert}-creds/${cert}.csr \
        -config ${cert}-creds/${cert}.cnf \
        -nodes

    # Sign CSR with CA
    openssl x509 -req \
        -days 3650 \
        -in ${cert}-creds/${cert}.csr \
        -CA ca.crt \
        -CAkey ca.key \
        -CAcreateserial \
        -out ${cert}-creds/${cert}.crt \
        -extfile ${cert}-creds/${cert}.cnf \
        -extensions v3_req

    # Export PKCS12 including only server cert + CA cert (do NOT include CA private key)
    openssl pkcs12 -export \
        -in ${cert}-creds/${cert}.crt \
        -inkey ${cert}-creds/${cert}.key \
        -chain \
        -CAfile ca.crt \
        -name ${cert} \
        -out ${cert}-creds/${cert}.p12 \
        -password pass:$SSL_PASSWORD

    # Convert to JKS keystore for Schema Registry
    keytool -importkeystore \
        -deststorepass $SSL_PASSWORD \
        -destkeystore ${cert}-creds/${cert}-keystore.jks \
        -srckeystore ${cert}-creds/${cert}.p12 \
        -deststoretype JKS \
        -srcstoretype PKCS12 \
        -noprompt \
        -srcstorepass $SSL_PASSWORD

    # Save passwords
    echo $SSL_PASSWORD > ${cert}-creds/${cert}_sslkey_creds
    echo $SSL_PASSWORD > ${cert}-creds/${cert}_keystore_creds
}

# ========================
# Main
# ========================
create_ca

# Broker creds
for cert in "broker"; do
    create_broker_creds ${cert}
done

# Schema Registry creds
create_schema_registry_creds

echo "All certificates created successfully."
