# Mata Elang Defense Center
---

## Description
Mata Elang Defense Center is a Mata Elang Platforms that provides a centralized security monitoring and management system for the Mata Elang Platforms. It is a centralized security monitoring and management system that provides real-time visibility of security alerts and incidents, and enables the Mata Elang Platforms to respond to security incidents in a timely manner.

## Components
Mata Elang Defense Center consists of the following components:
- Dashboard: Provides a real-time view of security alerts and incidents, and enables the Mata Elang Platforms to respond to security incidents in a timely manner.
- Reporting (Add-on): Provides detailed reports on security alerts and incidents, and enables the Mata Elang Platforms to analyze security trends and patterns.
- OpenCTI Integration (Add-on): Provides integration with OpenCTI, an open-source threat intelligence platform, to enable the Mata Elang Platforms to correlate security alerts and incidents with threat intelligence data.

## Features
Mata Elang Defense Center provides the following features:
- Real-time visibility of security alerts and incidents
- Centralized security monitoring and management
- Automated incident response
- Integration with OpenCTI
- Detailed reporting and analysis

## Add-ons
Mata Elang Defense Center provides the following add-ons:

### Mata Elang Report Generator
Mata Elang Report Generator is an add-on that provides detailed reports on security alerts and incidents. It enables the Mata Elang Platforms to analyze security trends and patterns.

**Features:**
- Generate reports on security alerts and incidents
- Analyze security trends and patterns
- Export reports in PDF
- Automate report generation for Daily, Monthly, Quarterly, and Yearly reports


### OpenCTI Integration
The OpenCTI Integration add-on provides integration with OpenCTI, an open-source threat intelligence platform. It enables the Mata Elang Platforms to correlate security alerts and incidents with threat intelligence data.

## Pre-requisites
- [Docker and Docker Compose](https://docs.docker.com/get-docker/)

## Installation
1. **Preparation**: Clone the repository and navigate to the `defense_center` directory.
    ```bash
    git clone https:// && cd defense_center
    ```
2. **Configuration**: Copy the example configuration file and update the configuration settings.
    ```bash
    cp .env.example .env
    ```

3. **Pull Images**: Pull the required Docker images.
    ```bash
    docker-compose pull
    ```

4. **Start Services**: Start the Docker services.
    ```bash
    docker-compose up -d
    ```

5. **Access Dashboard**: Access the Mata Elang Defense Center dashboard at http://localhost:5601.

## Mutual TLS (mTLS) for Kafka

This project supports mutual TLS between clients and the Kafka broker. The repo contains CNF templates for client certificates:
- `certs/event-stream-aggr-creds/event-stream-aggr.cnf`
- `certs/sensor-api-creds/sensor-api.cnf`
- `certs/kafka-ui-creds/kafka-ui.cnf`
 - `certs/logstash-creds/logstash.cnf`
 - If you don't want to create per-client CNF files manually, copy `certs/client-default.cnf` and replace `__COMMON_NAME__` with the client CN (e.g., `event-stream-aggr`).
    For example:
     ```bash
     cp certs/client-default.cnf certs/event-stream-aggr-creds/event-stream-aggr.cnf
     sed -i 's/__COMMON_NAME__/event-stream-aggr/g' certs/event-stream-aggr-creds/event-stream-aggr.cnf
     ```

To generate the CA, server and client certificates and keystores, run:
```bash
cd defense_center
cp .env.example .env  # if not already created
./scripts/create-broker-keystore.sh
```

The script will produce the broker keystore, `truststore.jks`, and client certs under `certs/*-creds/`.
The `docker-compose` services are configured to mount these certificates and enable mTLS.

Note: The script requires that a per-client CNF file is present in `certs/<client>-creds/<client>.cnf` when generating client certificates. If the CNF is missing, the script will print instructions to copy `certs/client-default.cnf` and exit to let you confirm the CNF content for each client.
Make sure `SSL_PASSWORD` (in `.env`) is set and the script runs successfully before `docker-compose up -d`.

### Go clients: sensor-api and event-stream-aggr (PKCS#12 keystore)

The Go-based clients `sensor-api` and `event-stream-aggr` accept PKCS#12 keystores to simplify client certificate management.
Mount the PKCS#12 keystore and CA PEM into the containers and set the following environment variables (examples):

```yaml
# Volumes
 - ./certs/ca.pem:/app/ca.pem:ro
 - ./certs/sensor-api-creds/sensor-api.p12:/app/sensor-client.p12:ro

# Environment (sensor-api)
 - MES_SERVER_PATH_TO_CLIENT_KEYSTORE=/app/sensor-client.p12
 - MES_SERVER_CLIENT_KEYSTORE_PASSWORD=${SSL_PASSWORD:-SslSecurePassword@123}

# Environment (event-stream-aggr)
 - PATH_TO_CLIENT_KEYSTORE=/app/event-stream-client.p12
 - CLIENT_KEYSTORE_PASSWORD=${SSL_PASSWORD:-SslSecurePassword@123}
```

The Go clients use PKCS#12 keystores (recommended). PEM files are no longer mounted by default. If you need to re-enable PEM-based client authentication, see the older revision of `defense_center/compose.yml`.

### Deploying Add-ons

#### Mata Elang Report Generator**: 

##### Prerequisites
- [GeoLite2 City and ASN Database](https://dev.maxmind.com/geoip/geoip2/geolite2/) in mmdb format.


##### Preparation
**Place GeoLite2 Databases**: Place the GeoLite2 City and ASN databases in the `geoip` directory.
```bash
cp /path/to/GeoLite2-City.mmdb files/GeoLite2-City.mmdb
cp /path/to/GeoLite2-ASN.mmdb files/GeoLite2-ASN.mmdb
```

> **Note:**  
> The filename for the GeoLite2 City and ASN databases should be `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` respectively.
> Otherwise, you need to update the [compose.reporting.yml in line 42-43](compose.reporting.yml#L42-L43).

##### Deployment
To deploy the Mata Elang Reporting add-on, run the following command:
```bash
docker-compose -f docker-compose.reporting.yml up -d
```

Access the Mata Elang Reporting dashboard at http://localhost:8085.

#### OpenCTI Integration
    
The OpenCTI Integration add-on requires the OpenCTI platform to be deployed separately. Go to the [OpenCTI Installation Guide](https://docs.opencti.io/latest/deployment/installation/) for more information.

Update the `OPENCTI_URL` and `OPENCTI_TOKEN` environment variables in the `.env` file to configure the OpenCTI Integration.

To deploy the OpenCTI Integration add-on, run the following command:
```bash
docker-compose -f docker-compose.opencti-connector.yml up -d
```
