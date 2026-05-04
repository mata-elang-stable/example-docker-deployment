#!/bin/bash

# -----------------------------------------------------------------------------
# Mata Elang SSL Certificate Generator
# -----------------------------------------------------------------------------
# Generates CA, truststore, client/service certificates, and OpenSearch
# certificates from a single TOML configuration file.
# -----------------------------------------------------------------------------

set -euo pipefail

# -----------------------------------------------------------------------------
# Colors
# -----------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# -----------------------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------------------
DEFAULT_CONFIG_FILE="config.toml"
DEFAULT_OUTPUT_DIR="./ssl_certs"

# -----------------------------------------------------------------------------
# Global Config Variables
# -----------------------------------------------------------------------------
CONFIG_FILE=""
OUTPUT_DIR=""
FORCE=false

# CA config
CA_COMMON_NAME=""
CA_ORGANIZATION=""
CA_COUNTRY=""
CA_STATE=""
CA_LOCALITY=""
CA_DAYS_VALID=3650
CA_KEY_SIZE=4096

# SSL config
SSL_PASSWORD=""

# Output config
OUTPUT_DIRECTORY=""

# Clients arrays (indexed)
declare -a CLIENT_NAMES
declare -a CLIENT_DNS
declare -a CLIENT_IPS
declare -a CLIENT_KEYSTORE_TYPES
declare -a CLIENT_KEYSTORE_FILENAMES
CLIENT_COUNT=0

# OpenSearch config
OS_NODE_NAME=""
OS_DNS=""
OS_IP=""

# Counters
GENERATED_COUNT=0
SKIPPED_COUNT=0

# -----------------------------------------------------------------------------
# Utility Functions
# -----------------------------------------------------------------------------

error_exit() {
    echo -e "${RED}Error: $1${NC}" >&2
    exit 1
}

check_dependency() {
    local cmd="$1"
    local pkg="$2"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        error_exit "${cmd} not found. Install it: ${pkg}"
    fi
}

show_help() {
    cat << EOF
Usage: ./generate.sh [OPTIONS]

Generate CA, truststore, client certificates, and OpenSearch SSL certificates
from a TOML configuration file.

Options:
  -h, --help              Show this help message
  -c, --config FILE       Configuration file (default: config.toml)
  -o, --output DIR        Output directory (overrides config)
      --force             Regenerate all certificates, ignore idempotency

Examples:
  ./generate.sh                           # Use default config.toml
  ./generate.sh --config custom.toml      # Use custom config file
  ./generate.sh --output /etc/ssl/certs   # Override output directory
  ./generate.sh --force                   # Regenerate everything

Dependencies:
  - openssl
  - keytool (from OpenJDK/JRE)

EOF
}

# -----------------------------------------------------------------------------
# TOML Parser Functions
# -----------------------------------------------------------------------------

parse_toml_array() {
    local value="$1"
    # Trim whitespace
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"

    # Check if it's an array
    if [[ ! "$value" == \[* ]]; then
        echo ""
        return
    fi

    value="${value#\[}"
    value="${value%\]}"

    local result=""
    IFS=',' read -ra parts <<< "$value"
    for part in "${parts[@]}"; do
        part="${part#"${part%%[![:space:]]*}"}"
        part="${part%"${part##*[![:space:]]}"}"
        # Remove quotes
        if [[ "$part" =~ ^\"(.*)\"$ ]]; then
            part="${BASH_REMATCH[1]}"
        fi
        if [[ -n "$part" ]]; then
            result="$result$part "
        fi
    done
    # Trim trailing space
    result="${result%"${result##*[![:space:]]}"}"
    echo "$result"
}

parse_toml() {
    local config_file="$1"

    [[ -f "$config_file" ]] || error_exit "Configuration file not found: $config_file"

    local current_section=""
    local in_clients=false

    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" =~ ^[[:space:]]*$ ]] && continue

        # Parse array of tables: [[clients]]
        if [[ "$line" =~ ^[[:space:]]*\[\[([a-zA-Z_]+)\]\][[:space:]]*$ ]]; then
            current_section="${BASH_REMATCH[1]}"
            in_clients=false
            if [[ "$current_section" == "clients" ]]; then
                in_clients=true
                CLIENT_COUNT=$((CLIENT_COUNT + 1))
            fi
            continue
        fi

        # Parse section headers: [ca], [ssl], etc.
        if [[ "$line" =~ ^[[:space:]]*\[([a-zA-Z_]+)\][[:space:]]*$ ]]; then
            current_section="${BASH_REMATCH[1]}"
            in_clients=false
            continue
        fi

        # Parse key-value pairs
        if [[ "$line" =~ ^[[:space:]]*([a-zA-Z_]+)[[:space:]]*=[[:space:]]*(.+)[[:space:]]*$ ]]; then
            local key="${BASH_REMATCH[1]}"
            local value="${BASH_REMATCH[2]}"

            # Strip inline comments (everything after first unquoted #)
            value="${value%%#*}"

            # Trim whitespace from value
            value="${value#"${value%%[![:space:]]*}"}"
            value="${value%"${value##*[![:space:]]}"}"

            # Remove quotes from string values
            if [[ "$value" =~ ^\"(.*)\"$ ]]; then
                value="${BASH_REMATCH[1]}"
            fi

            if [[ "$in_clients" == true && "$current_section" == "clients" ]]; then
                local idx=$((CLIENT_COUNT - 1))
                case "$key" in
                    "name") CLIENT_NAMES[idx]="$value" ;;
                    "dns") CLIENT_DNS[idx]="$(parse_toml_array "$value")" ;;
                    "ip") CLIENT_IPS[idx]="$(parse_toml_array "$value")" ;;
                    "keystore_type") CLIENT_KEYSTORE_TYPES[idx]="$value" ;;
                    "keystore_filename") CLIENT_KEYSTORE_FILENAMES[idx]="$value" ;;
                esac
            else
                case "$current_section" in
                    "ca")
                        case "$key" in
                            "common_name") CA_COMMON_NAME="$value" ;;
                            "organization") CA_ORGANIZATION="$value" ;;
                            "country") CA_COUNTRY="$value" ;;
                            "state") CA_STATE="$value" ;;
                            "locality") CA_LOCALITY="$value" ;;
                            "days_valid") CA_DAYS_VALID="$value" ;;
                            "key_size") CA_KEY_SIZE="$value" ;;
                        esac
                        ;;
                    "ssl")
                        case "$key" in
                            "password") SSL_PASSWORD="$value" ;;
                        esac
                        ;;
                    "output")
                        case "$key" in
                            "directory") OUTPUT_DIRECTORY="$value" ;;
                        esac
                        ;;
                    "opensearch")
                        case "$key" in
                            "node_name") OS_NODE_NAME="$value" ;;
                            "dns") OS_DNS="$(parse_toml_array "$value")" ;;
                            "ip") OS_IP="$(parse_toml_array "$value")" ;;
                        esac
                        ;;
                esac
            fi
        fi
    done < "$config_file"
}

# -----------------------------------------------------------------------------
# Validation Functions
# -----------------------------------------------------------------------------

validate_config() {
    [[ -n "$CA_COMMON_NAME" ]] || error_exit "common_name is required in [ca] section"
    [[ -n "$SSL_PASSWORD" ]] || error_exit "password is required in [ssl] section"

    # Validate CA days_valid
    if [[ -n "$CA_DAYS_VALID" ]]; then
        [[ "$CA_DAYS_VALID" =~ ^[0-9]+$ ]] || error_exit "ca.days_valid must be a positive integer"
        [[ "$CA_DAYS_VALID" -gt 0 ]] || error_exit "ca.days_valid must be greater than 0"
    fi

    # Validate CA key_size
    if [[ -n "$CA_KEY_SIZE" ]]; then
        [[ "$CA_KEY_SIZE" =~ ^[0-9]+$ ]] || error_exit "ca.key_size must be an integer"
    fi

    # Validate clients
    [[ "$CLIENT_COUNT" -gt 0 ]] || error_exit "At least one [[clients]] entry is required"

    local i
    for ((i=0; i<CLIENT_COUNT; i++)); do
        [[ -n "${CLIENT_NAMES[i]}" ]] || error_exit "name is required for each [[clients]] entry"
    done
}

# -----------------------------------------------------------------------------
# Certificate Helper Functions
# -----------------------------------------------------------------------------

is_cert_valid() {
    local cert_file="$1"
    local seconds=$((60 * 24 * 60 * 60))  # 60 days in seconds

    if [[ ! -f "$cert_file" ]]; then
        return 1
    fi

    if ! openssl x509 -in "$cert_file" -noout -checkend "$seconds" >/dev/null 2>&1; then
        return 1
    fi

    return 0
}

create_client_cnf() {
    local cnf_file="$1"
    local common_name="$2"
    local dns_sans="$3"
    local ip_sans="$4"

    cat > "$cnf_file" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = ${common_name}
EOF
    [[ -n "$CA_ORGANIZATION" ]] && echo "O = ${CA_ORGANIZATION}" >> "$cnf_file"
    [[ -n "$CA_COUNTRY" ]] && echo "C = ${CA_COUNTRY}" >> "$cnf_file"
    [[ -n "$CA_STATE" ]] && echo "ST = ${CA_STATE}" >> "$cnf_file"
    [[ -n "$CA_LOCALITY" ]] && echo "L = ${CA_LOCALITY}" >> "$cnf_file"

    cat >> "$cnf_file" << EOF

[v3_req]
keyUsage = keyEncipherment, dataEncipherment, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
EOF

    if [[ -n "$dns_sans" || -n "$ip_sans" ]]; then
        cat >> "$cnf_file" << EOF
subjectAltName = @alt_names

[alt_names]
EOF

        local idx=1
        local dns
        set -f  # disable globbing
        for dns in $dns_sans; do
            echo "DNS.${idx} = ${dns}" >> "$cnf_file"
            idx=$((idx + 1))
        done
        set +f  # re-enable globbing

        idx=1
        local ip
        set -f  # disable globbing
        for ip in $ip_sans; do
            echo "IP.${idx} = ${ip}" >> "$cnf_file"
            idx=$((idx + 1))
        done
        set +f  # re-enable globbing
    fi
}

# -----------------------------------------------------------------------------
# Generation Functions
# -----------------------------------------------------------------------------

generate_ca() {
    local ca_dir="${OUTPUT_DIR}/ca"
    local ca_key="${ca_dir}/ca.key"
    local ca_crt="${ca_dir}/ca.crt"

    mkdir -p "$ca_dir"

    if [[ "$FORCE" == true ]]; then
        rm -f "$ca_key" "$ca_crt" "${ca_dir}/ca.srl"
    fi

    if [[ "$FORCE" == false ]] && is_cert_valid "$ca_crt" && [[ -f "$ca_key" ]]; then
        echo -e "${YELLOW}  ⏭️  CA certificate is valid, skipping${NC}"
        return 1
    fi

    echo -e "${BLUE}  📝 Generating CA private key (${CA_KEY_SIZE} bits)...${NC}"
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:"${CA_KEY_SIZE}" -out "$ca_key"
    chmod 600 "$ca_key"

    echo -e "${BLUE}  📝 Generating CA certificate...${NC}"
    local subject=""
    [[ -n "$CA_COUNTRY" ]] && subject="${subject}/C=${CA_COUNTRY}"
    [[ -n "$CA_STATE" ]] && subject="${subject}/ST=${CA_STATE}"
    [[ -n "$CA_LOCALITY" ]] && subject="${subject}/L=${CA_LOCALITY}"
    [[ -n "$CA_ORGANIZATION" ]] && subject="${subject}/O=${CA_ORGANIZATION}"
    subject="${subject}/CN=${CA_COMMON_NAME}"

    openssl req -new -x509 -key "$ca_key" -subj "$subject" \
        -days "$CA_DAYS_VALID" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash" \
        -out "$ca_crt" || error_exit "Failed to create CA certificate"
    echo -e "${GREEN}  ✅ CA certificate generated${NC}"
    return 0
}

generate_truststore() {
    check_dependency "keytool" "sudo apt install default-jre-headless"

    local ts_dir="${OUTPUT_DIR}/truststore"
    local ts_jks="${ts_dir}/truststore.jks"
    local ts_creds="${ts_dir}/truststore_creds"
    local ca_crt="${OUTPUT_DIR}/ca/ca.crt"

    mkdir -p "$ts_dir"

    if [[ "$FORCE" == true ]]; then
        rm -f "$ts_jks"
    fi

    if [[ "$FORCE" == false ]] && [[ -f "$ts_jks" ]] && is_cert_valid "$ca_crt"; then
        echo -e "${YELLOW}  ⏭️  Truststore exists and CA is valid, skipping${NC}"
        return 1
    fi

    echo -e "${BLUE}  📝 Creating Java truststore...${NC}"
    keytool -import -alias mataelang-ca -file "$ca_crt" \
        -keystore "$ts_jks" -storetype JKS \
        -storepass "$SSL_PASSWORD" -noprompt || error_exit "Failed to create truststore"

    echo "$SSL_PASSWORD" > "$ts_creds"
    echo -e "${GREEN}  ✅ Truststore generated${NC}"
    return 0
}

generate_client_cert() {
    local idx="$1"
    local name="${CLIENT_NAMES[idx]}"
    local dns_sans="${CLIENT_DNS[idx]:-}"
    local ip_sans="${CLIENT_IPS[idx]:-}"
    local keystore_type="${CLIENT_KEYSTORE_TYPES[idx]:-pkcs12}"
    local keystore_filename="${CLIENT_KEYSTORE_FILENAMES[idx]:-}"

    local client_dir="${OUTPUT_DIR}/${name}"
    local cert_key="${client_dir}/${name}.key"
    local cert_csr="${client_dir}/${name}.csr"
    local cert_crt="${client_dir}/${name}.crt"
    local cert_p12="${client_dir}/${name}.p12"
    local ca_key="${OUTPUT_DIR}/ca/ca.key"
    local ca_crt="${OUTPUT_DIR}/ca/ca.crt"

    mkdir -p "$client_dir"

    if [[ "$FORCE" == true ]]; then
        rm -f "$cert_key" "$cert_csr" "$cert_crt" "$cert_p12"
        rm -f "${client_dir}/${name}-keystore.jks"
        if [[ -n "$keystore_filename" ]]; then
            rm -f "${client_dir}/${keystore_filename}"
        fi
    fi

    if [[ "$FORCE" == false ]] && is_cert_valid "$cert_crt" && [[ -f "$cert_key" ]] && [[ -f "$cert_p12" ]]; then
        echo -e "${YELLOW}  ⏭️  ${name} certificate is valid, skipping${NC}"
        return 1
    fi

    echo -e "${BLUE}  📝 Generating ${name} certificate...${NC}"

    # Create OpenSSL config with SANs
    local cnf_file="${client_dir}/${name}.cnf"
    create_client_cnf "$cnf_file" "$name" "$dns_sans" "$ip_sans"

    # Generate private key
    openssl genrsa -out "$cert_key" 2048 || error_exit "Failed to generate key for ${name}"

    # Create CSR
    openssl req -new -key "$cert_key" -out "$cert_csr" -config "$cnf_file" || error_exit "Failed to create CSR for ${name}"

    # Sign with CA
    openssl x509 -req -in "$cert_csr" \
        -CA "$ca_crt" -CAkey "$ca_key" -CAcreateserial \
        -out "$cert_crt" \
        -days 3650 \
        -extensions v3_req -extfile "$cnf_file" || error_exit "Failed to sign certificate for ${name}"

    # Create PKCS12 keystore
    openssl pkcs12 -export -in "$cert_crt" -inkey "$cert_key" \
        -chain -CAfile "$ca_crt" \
        -name "$name" \
        -out "$cert_p12" \
        -password pass:"$SSL_PASSWORD" || error_exit "Failed to create PKCS12 for ${name}"

    # Convert to JKS if needed
    if [[ "$keystore_type" == "jks" ]]; then
        local jks_file="${client_dir}/${name}-keystore.jks"
        keytool -importkeystore \
            -deststorepass "$SSL_PASSWORD" \
            -destkeystore "$jks_file" \
            -srckeystore "$cert_p12" \
            -deststoretype JKS \
            -srcstoretype PKCS12 \
            -noprompt \
            -srcstorepass "$SSL_PASSWORD"
    fi

    # Create custom keystore filename if specified
    if [[ -n "$keystore_filename" ]]; then
        local custom_file="${client_dir}/${keystore_filename}"
        if [[ "$keystore_filename" == *.jks ]]; then
            keytool -importkeystore \
                -deststorepass "$SSL_PASSWORD" \
                -destkeystore "$custom_file" \
                -srckeystore "$cert_p12" \
                -deststoretype JKS \
                -srcstoretype PKCS12 \
                -noprompt \
                -srcstorepass "$SSL_PASSWORD"
        else
            cp "$cert_p12" "$custom_file"
        fi
    fi

    # Write credential files
    echo "$SSL_PASSWORD" > "${client_dir}/${name}_keystore_creds"
    echo "$SSL_PASSWORD" > "${client_dir}/${name}_sslkey_creds"

    # Cleanup intermediate files
    rm -f "$cert_csr" "$cnf_file"

    echo -e "${GREEN}  ✅ ${name} certificate generated${NC}"
    return 0
}

generate_opensearch_cert() {
    local os_dir="${OUTPUT_DIR}/opensearch"
    local node_name="${OS_NODE_NAME}"
    local dns_sans="${OS_DNS}"
    local ip_sans="${OS_IP}"
    local ca_key="${OUTPUT_DIR}/ca/ca.key"
    local ca_crt="${OUTPUT_DIR}/ca/ca.crt"

    local cert_key="${os_dir}/${node_name}-key.pem"
    local cert_csr="${os_dir}/${node_name}.csr"
    local cert_pem="${os_dir}/${node_name}.pem"

    mkdir -p "$os_dir"

    if [[ "$FORCE" == true ]]; then
        rm -f "$cert_key" "$cert_csr" "$cert_pem"
    fi

    if [[ "$FORCE" == false ]] && is_cert_valid "$cert_pem" && [[ -f "$cert_key" ]]; then
        echo -e "${YELLOW}  ⏭️  OpenSearch certificate is valid, skipping${NC}"
        return 1
    fi

    echo -e "${BLUE}  📝 Generating OpenSearch certificate...${NC}"

    # Create OpenSSL config with SANs
    local cnf_file="${os_dir}/${node_name}.cnf"
    create_client_cnf "$cnf_file" "$node_name" "$dns_sans" "$ip_sans"

    # Generate private key
    openssl genrsa -out "$cert_key" 2048 || error_exit "Failed to generate OpenSearch key"

    # Create CSR
    openssl req -new -key "$cert_key" -out "$cert_csr" -config "$cnf_file" || error_exit "Failed to create OpenSearch CSR"

    # Sign with CA
    openssl x509 -req -in "$cert_csr" \
        -CA "$ca_crt" -CAkey "$ca_key" -CAcreateserial \
        -out "$cert_pem" \
        -days 3650 \
        -extensions v3_req -extfile "$cnf_file" || error_exit "Failed to sign OpenSearch certificate"

    # Set permissions
    chmod 644 "$cert_pem"
    chmod 640 "$cert_key"

    # Cleanup intermediate files
    rm -f "$cert_csr" "$cnf_file"

    echo -e "${GREEN}  ✅ OpenSearch certificate generated${NC}"
    return 0
}

# -----------------------------------------------------------------------------
# Main Script
# -----------------------------------------------------------------------------

main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --force)
                FORCE=true
                shift
                ;;
            *)
                error_exit "Unknown option: $1. Use --help for usage information."
                ;;
        esac
    done

    # Set defaults
    CONFIG_FILE="${CONFIG_FILE:-$DEFAULT_CONFIG_FILE}"

    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           Mata Elang SSL Certificate Generator               ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    # Parse configuration
    echo -e "${BOLD}📖 Reading configuration from: ${CONFIG_FILE}${NC}"
    parse_toml "$CONFIG_FILE"

    # Set output directory priority: CLI > config > default
    if [[ -z "$OUTPUT_DIR" ]]; then
        OUTPUT_DIR="${OUTPUT_DIRECTORY:-$DEFAULT_OUTPUT_DIR}"
    fi

    # Validate configuration
    validate_config

    # Create output directory
    mkdir -p "$OUTPUT_DIR" || error_exit "Cannot create output directory: $OUTPUT_DIR"

    if command -v realpath >/dev/null 2>&1; then
        echo -e "${BOLD}📁 Output directory: $(realpath "$OUTPUT_DIR")${NC}"
    else
        echo -e "${BOLD}📁 Output directory: ${OUTPUT_DIR}${NC}"
    fi
    echo ""

    # Generate CA
    echo -e "${BOLD}🔐 Generating CA Certificate...${NC}"
    if generate_ca; then
        GENERATED_COUNT=$((GENERATED_COUNT + 1))
    else
        SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
    fi
    echo ""

    # Generate Truststore
    echo -e "${BOLD}🔐 Generating Truststore...${NC}"
    if generate_truststore; then
        GENERATED_COUNT=$((GENERATED_COUNT + 1))
    else
        SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
    fi
    echo ""

    # Generate Client Certificates
    echo -e "${BOLD}🔐 Generating Client Certificates (${CLIENT_COUNT} clients)...${NC}"
    local i
    for ((i=0; i<CLIENT_COUNT; i++)); do
        if generate_client_cert "$i"; then
            GENERATED_COUNT=$((GENERATED_COUNT + 1))
        else
            SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
        fi
    done
    echo ""

    # Generate OpenSearch Certificate
    if [[ -n "$OS_NODE_NAME" ]]; then
        echo -e "${BOLD}🔐 Generating OpenSearch Certificate...${NC}"
        if generate_opensearch_cert; then
            GENERATED_COUNT=$((GENERATED_COUNT + 1))
        else
            SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
        fi
        echo ""
    fi

    # Summary
    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                      Generation Summary                      ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  ${GREEN}Generated: ${GENERATED_COUNT}${NC}"
    echo -e "  ${YELLOW}Skipped (valid): ${SKIPPED_COUNT}${NC}"
    echo ""

    echo -e "${BOLD}📂 Output Structure:${NC}"
    echo "  ${OUTPUT_DIR}/"
    echo "  ├── ca/"
    echo "  │   ├── ca.key"
    echo "  │   └── ca.crt"
    echo "  ├── truststore/"
    echo "  │   ├── truststore.jks"
    echo "  │   └── truststore_creds"

    for ((i=0; i<CLIENT_COUNT; i++)); do
        local name="${CLIENT_NAMES[i]}"
        local keystore_type="${CLIENT_KEYSTORE_TYPES[i]:-pkcs12}"
        local keystore_filename="${CLIENT_KEYSTORE_FILENAMES[i]:-}"
        echo "  ├── ${name}/"
        echo "  │   ├── ${name}.p12"
        if [[ "$keystore_type" == "jks" ]]; then
            echo "  │   ├── ${name}-keystore.jks"
        fi
        if [[ -n "$keystore_filename" ]]; then
            echo "  │   ├── ${keystore_filename}"
        fi
        echo "  │   ├── ${name}_keystore_creds"
        echo "  │   └── ${name}_sslkey_creds"
    done

    if [[ -n "$OS_NODE_NAME" ]]; then
        echo "  └── opensearch/"
        echo "      ├── ${OS_NODE_NAME}.pem"
        echo "      └── ${OS_NODE_NAME}-key.pem"
    fi

    echo ""
    echo -e "${BOLD}💡 Next Steps:${NC}"
    echo "  1. Review certificates in the output directory"
    echo "  2. Validate CA with: ./validate.sh ${OUTPUT_DIR}/ca/ca.crt"
    echo "  3. Mount certificates in your docker-compose or Kubernetes manifests"
    echo ""
    echo -e "${GREEN}✅ Done!${NC}"
}

# Run main function with all arguments
main "$@"
