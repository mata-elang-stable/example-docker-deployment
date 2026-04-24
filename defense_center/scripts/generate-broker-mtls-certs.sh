#!/bin/bash

set -e
cd ..
if [ -f .env ]; then
    source .env
fi
cd certs

CHANGES_MADE=0

# Configuration with defaults
# Renew if expiring within X days (default 30)
RENEW_THRESHOLD_DAYS=${CERT_RENEW_THRESHOLD_DAYS:-30}
RENEW_THRESHOLD_SECONDS=$((RENEW_THRESHOLD_DAYS * 86400))

# Validity for new certificates in days (default 3650 = ~10 years)
VALIDITY_DAYS=${CERT_VALIDITY_DAYS:-3650}

echo "Configuration:"
echo "  Renew threshold: $RENEW_THRESHOLD_DAYS days ($RENEW_THRESHOLD_SECONDS seconds)"
echo "  Validity period: $VALIDITY_DAYS days"

# Helper to check if cert needs renewal
# Returns 0 if needs renewal (missing or expired), 1 if valid
check_cert_needs_renewal() {
    local cert_path=$1
    if [ ! -f "$cert_path" ]; then
        echo "Certificate $cert_path missing. Generating..."
        return 0
    fi
    
    # Check if expired within threshold
    if openssl x509 -checkend "$RENEW_THRESHOLD_SECONDS" -noout -in "$cert_path"; then
        echo "Certificate $cert_path is valid (expires > $RENEW_THRESHOLD_DAYS days). Skipping."
        return 1
    else
        echo "Certificate $cert_path is expired or expiring within $RENEW_THRESHOLD_DAYS days. Renewing..."
        return 0
    fi
}

# Helper to create default CNF if missing
create_default_cnf() {
    local cert=$1
    local cnf_path="${cert}-creds/${cert}.cnf"
    
    if [ -f "$cnf_path" ]; then
        return
    fi
    
    echo "Generating default configuration for $cert..."
    mkdir -p "${cert}-creds"
    
    cat > "$cnf_path" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
O = MATAELANG
L = MountainView
CN = $cert

[v3_req]
keyUsage = keyEncipherment, dataEncipherment, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $cert
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF
}

# ========================
# Create CA
# ========================
create_ca() {
    # Expect ca.crt and ca.key to be present in ca-creds/
    if [ ! -f "ca-creds/ca.crt" ]; then
        echo "Error: ca-creds/ca.crt not found in $(pwd). Please mount the CA certificate to this location."
        exit 1
    fi
    if [ ! -f "ca-creds/ca.key" ]; then
        echo "Error: ca-creds/ca.key not found in $(pwd). Please mount the CA key to this location."
        exit 1
    fi

    # Check if we need to update truststore
    local need_update=0
    mkdir -p truststore
    if [ ! -f "truststore/truststore.jks" ] || [ ! -f "ca-creds/ca.pem" ]; then
        need_update=1
    else
        # Check if ca.crt content changed vs ca.pem
        if ! cmp -s ca-creds/ca.crt ca-creds/ca.pem; then
            need_update=1
        fi
    fi

    if [ $need_update -eq 0 ]; then
        echo "CA and truststore up to date."
        return
    fi

    echo "Using existing CA found in $(pwd)/ca-creds..."

    # Clean up old generated files
    rm -f truststore/truststore.jks ca-creds/ca.pem

    # PEM for client services
    cp ca-creds/ca.crt ca-creds/ca.pem

    # Java truststore for Kafka UI / Schema Registry
    keytool -import -alias mataelang-ca \
        -file ca-creds/ca.crt \
        -keystore truststore/truststore.jks \
        -storepass $SSL_PASSWORD -noprompt
    
    # Save truststore creds
    echo $SSL_PASSWORD > truststore/truststore_creds
    
    CHANGES_MADE=1
}

# ========================
# Create Broker Credentials
# ========================
create_broker_creds() {
    local cert=$1
    
    if ! check_cert_needs_renewal "${cert}-creds/${cert}.crt"; then
        return
    fi

    echo "Creating broker credentials for $cert..."

    mkdir -p ${cert}-creds
    create_default_cnf ${cert}

    # Generate key + CSR
    openssl req -new \
        -newkey rsa:2048 \
        -keyout ${cert}-creds/${cert}.key \
        -out ${cert}-creds/${cert}.csr \
        -config ${cert}-creds/${cert}.cnf \
        -nodes

    # Sign CSR with CA
    openssl x509 -req \
        -days $VALIDITY_DAYS \
        -in ${cert}-creds/${cert}.csr \
        -CA ca-creds/ca.crt \
        -CAkey ca-creds/ca.key \
        -CAcreateserial \
        -out ${cert}-creds/${cert}.crt \
        -extfile ${cert}-creds/${cert}.cnf \
        -passin pass:$SSL_PASSWORD \
        -extensions v3_req

    # Export PKCS12 including only server cert + CA cert (chain)
    openssl pkcs12 -export \
        -in ${cert}-creds/${cert}.crt \
        -inkey ${cert}-creds/${cert}.key \
        -chain \
        -CAfile ca-creds/ca.crt \
        -name ${cert} \
        -out ${cert}-creds/${cert}.p12 \
        -password pass:$SSL_PASSWORD
    
    # Make .p12 file readable
    chmod 644 ${cert}-creds/${cert}.p12

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
    
    CHANGES_MADE=1
}

# ========================
# Create Schema Registry Credentials
# ========================
create_schema_registry_creds() {
    local cert="schema-registry"
    
    if ! check_cert_needs_renewal "${cert}-creds/${cert}.crt"; then
        return
    fi

    echo "Creating Schema Registry credentials..."

    mkdir -p ${cert}-creds
    create_default_cnf ${cert}

    # Generate key + CSR
    openssl req -new \
        -newkey rsa:2048 \
        -keyout ${cert}-creds/${cert}.key \
        -out ${cert}-creds/${cert}.csr \
        -config ${cert}-creds/${cert}.cnf \
        -nodes

    # Sign CSR with CA
    openssl x509 -req \
        -days $VALIDITY_DAYS \
        -in ${cert}-creds/${cert}.csr \
        -CA ca-creds/ca.crt \
        -CAkey ca-creds/ca.key \
        -CAcreateserial \
        -out ${cert}-creds/${cert}.crt \
        -extfile ${cert}-creds/${cert}.cnf \
        -passin pass:$SSL_PASSWORD \
        -extensions v3_req

    # Export PKCS12
    openssl pkcs12 -export \
        -in ${cert}-creds/${cert}.crt \
        -inkey ${cert}-creds/${cert}.key \
        -chain \
        -CAfile ca-creds/ca.crt \
        -name ${cert} \
        -out ${cert}-creds/${cert}.p12 \
        -password pass:$SSL_PASSWORD
    
    chmod 644 ${cert}-creds/${cert}.p12

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
    
    CHANGES_MADE=1
}

# ========================
# Create client (service) credentials
# ========================
create_client_creds() {
    local cert=$1
    local make_jks=$2
    
    if ! check_cert_needs_renewal "${cert}-creds/${cert}.crt"; then
        return
    fi

    echo "Creating client credentials for $cert..."

    mkdir -p ${cert}-creds
    create_default_cnf ${cert}

    # Generate key + CSR
    openssl req -new \
        -newkey rsa:2048 \
        -keyout ${cert}-creds/${cert}.key \
        -out ${cert}-creds/${cert}.csr \
        -config ${cert}-creds/${cert}.cnf \
        -nodes

    # Sign CSR with CA
    openssl x509 -req \
        -days $VALIDITY_DAYS \
        -in ${cert}-creds/${cert}.csr \
        -CA ca-creds/ca.crt \
        -CAkey ca-creds/ca.key \
        -CAcreateserial \
        -out ${cert}-creds/${cert}.crt \
        -extfile ${cert}-creds/${cert}.cnf \
        -passin pass:$SSL_PASSWORD \
        -extensions v3_req

    # Export PKCS12
    openssl pkcs12 -export \
        -in ${cert}-creds/${cert}.crt \
        -inkey ${cert}-creds/${cert}.key \
        -chain \
        -CAfile ca-creds/ca.crt \
        -name ${cert} \
        -out ${cert}-creds/${cert}.p12 \
        -password pass:$SSL_PASSWORD
    
    chmod 644 ${cert}-creds/${cert}.p12

    if [ "${make_jks}" = "true" ]; then
        keytool -importkeystore \
            -deststorepass $SSL_PASSWORD \
            -destkeystore ${cert}-creds/${cert}-keystore.jks \
            -srckeystore ${cert}-creds/${cert}.p12 \
            -deststoretype JKS \
            -srcstoretype PKCS12 \
            -noprompt \
            -srcstorepass $SSL_PASSWORD
    fi

    echo $SSL_PASSWORD > ${cert}-creds/${cert}_sslkey_creds
    echo $SSL_PASSWORD > ${cert}-creds/${cert}_keystore_creds
    
    CHANGES_MADE=1
}

# ========================
# Create OpenSearch Credentials
# OpenSearch Security Plugin uses raw PEM files, not JKS/PKCS12.
# Files must match exactly what is declared in opensearch-node1 environment:
#   pemcert_filepath   = certificates/opensearch-node1.pem
#   pemkey_filepath    = certificates/opensearch-node1-key.pem
#   pemtrustedcas_filepath = certificates/root-ca.pem
# ========================
create_opensearch_creds() {
    local dir="opensearch"
    local cert_file="${dir}/opensearch-node1.pem"

    if ! check_cert_needs_renewal "$cert_file"; then
        return
    fi

    echo "Creating OpenSearch SSL credentials..."
    mkdir -p "$dir"

    # Reuse the shared CA as the OpenSearch trusted CA
    # opensearch-node1 mounts ./certs/opensearch -> /usr/share/opensearch/config/certificates
    # so root-ca.pem must live inside that directory
    cp ca-creds/ca.crt "${dir}/root-ca.pem"

    # Use existing CNF if present (./certs/opensearch/opensearch-node.cnf)
    # Otherwise generate a default one
    local cnf="${dir}/opensearch-node.cnf"
    if [ ! -f "$cnf" ]; then
        echo "opensearch-node.cnf not found, generating default..."
        cat > "$cnf" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = ID
O = MataElang
CN = opensearch-node1

[v3_req]
keyUsage = keyEncipherment, dataEncipherment, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = opensearch-node1
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF
    fi

    # Generate node private key
    openssl genrsa -out "${dir}/opensearch-node1-key.pem" 2048

    # Generate CSR
    openssl req -new \
        -key "${dir}/opensearch-node1-key.pem" \
        -out "${dir}/opensearch-node1.csr" \
        -config "$cnf"

    # Sign with shared CA
    openssl x509 -req \
        -days $VALIDITY_DAYS \
        -in "${dir}/opensearch-node1.csr" \
        -CA ca-creds/ca.crt \
        -CAkey ca-creds/ca.key \
        -CAcreateserial \
        -out "${dir}/opensearch-node1.pem" \
        -extfile "$cnf" \
        -extensions v3_req

    # Cleanup CSR — not needed after signing
    rm -f "${dir}/opensearch-node1.csr"

    # OpenSearch runs as UID 1000 inside the container
    # key must be 600, certs 644
    chown ${HOST_UID:-1000}:${HOST_GID:-1000} "${dir}/root-ca.pem"
    chown ${HOST_UID:-1000}:${HOST_GID:-1000} "${dir}/opensearch-node1.pem"
    chown ${HOST_UID:-1000}:${HOST_GID:-1000} "${dir}/opensearch-node1-key.pem"

    chmod 644 "${dir}/root-ca.pem"
    chmod 644 "${dir}/opensearch-node1.pem"
    chmod 640 "${dir}/opensearch-node1-key.pem"

    echo "OpenSearch SSL credentials created."
    CHANGES_MADE=1
}

# ========================
# Main
# ========================
create_ca

# Broker
for cert in "broker"; do
    create_broker_creds ${cert}
done

# Schema Registry
create_schema_registry_creds

# Kafka clients
for client in "event-stream-aggr" "sensor-api" "kafka-ui" "logstash"; do
    if [ "$client" = "kafka-ui" ] || [ "$client" = "logstash" ]; then
        create_client_creds ${client} true
    else
        create_client_creds ${client} false
    fi
done

# OpenSearch
create_opensearch_creds

if [ $CHANGES_MADE -eq 1 ]; then
    echo "Certificates generated or renewed."
    exit 0
else
    echo "No certificates needed renewal."
    exit 0
fi