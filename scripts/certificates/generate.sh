#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
TMP_DIR=${SCRIPT_DIR}/tmp

pushd $SCRIPT_DIR

  # Clean up old data
  rm -f *.key
  rm -f *.crt
  rm -rf ${TMP_DIR}
  mkdir -p ${TMP_DIR}

  # Create a random passphrase for the private key
  echo -e "${GREEN}Generating passphrase for private keys${NC}"
  openssl rand -base64 48 > ${TMP_DIR}/privateKey.passphrase

  # Generate CA private key
  echo -e "${GREEN}Generating CA private key: ${RED}CA.key${NC}"
  openssl genrsa -des3 -passout file:${TMP_DIR}/privateKey.passphrase -out CA.key 4096
  # Remove Passphrase from Key
  cp CA.key ${TMP_DIR}/CA-original.key
  openssl rsa -in ${TMP_DIR}/CA-original.key -passin file:${TMP_DIR}/privateKey.passphrase -out CA.key
  rm -f ${TMP_DIR}/CA-original.key

  # Generate CA certificate in PEM format
  echo -e "${GREEN}Generating CA certificate: ${RED}CA.crt${NC}"
  openssl req -x509 -new -nodes -key CA.key -sha256 -days 3650 -out CA.crt \
    -subj "/C=US/ST=WA/L=Vancouver/O=Tanzu/OU=AppSSP/CN=localhost"

  # Generate server key and signing request
  echo -e "${GREEN}Generating a server private key: ${RED}server.key${NC}"
  openssl req -new -nodes -sha256 -out ${TMP_DIR}/server.csr -keyout server.key -newkey rsa:4096 \
    -subj "/C=US/ST=WA/L=Vancouver/O=Tanzu/OU=AppSSP/CN=localhost"

  # Generate signing config

  cat > ${TMP_DIR}/CA.conf <<EOL
[ ca ]
default_ca = ca_default
[ ca_default ]
certs = $TMP_DIR
new_certs_dir = $TMP_DIR/ca.db.certs
database = $TMP_DIR/ca.db.index
serial = $TMP_DIR/ca.db.serial
RANDFILE = $TMP_DIR/ca.db.rand
certificate = $TMP_DIR/CA.crt
private_key = $TMP_DIR/CA.key
default_days = 3650
default_crl_days = 30
default_md = sha256
preserve = no
policy = generic_policy
[ generic_policy ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = optional
emailAddress = optional

[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[req_distinguished_name]
commonName = Common Name
commonName_max = 64

[v3_req]
basicConstraints = critical,CA:TRUE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
EOL

  # Create openssl certificate database
  mkdir ${TMP_DIR}/ca.db.certs
  touch ${TMP_DIR}/ca.db.index
  echo "1234" > ${TMP_DIR}/ca.db.serial

  # sign the server certificate
  echo -e "${GREEN}Generating a signed server certificate: ${RED}server.crt${NC}"
  openssl ca -batch -config ${TMP_DIR}/CA.conf -out server.crt -notext -days 3650 -in ${TMP_DIR}/server.csr -keyfile CA.key -extensions v3_req -cert CA.crt

  # Delete the temporary data
  rm -rf ${TMP_DIR}

  # Create a PKCS12 Format Keystore (like uaa-release uses)
  KEYSTORE_FILE=uaa_keystore.p12
  if command -v openssl &> /dev/null; then
    cat server.crt > server.cert-and-key.crt
    cat server.key >> server.cert-and-key.crt

    openssl pkcs12 -export ${FIPS_OPTS} -name uaa_ssl_cert \
            -in server.cert-and-key.crt \
            -out uaa_keystore.p12 \
            -password pass:k0*l*s3cur1tyr0ck$
    chmod og+r uaa_keystore.p12
    chmod og+r server.cert-and-key.crt
  else
    echo -e "${RED}\`openssl\` does not exist in PATH, please install it!${NC}"
    KEYSTORE_FILE="<not created>"
  fi
  chmod og+r server.key
  chmod og+r server.crt
  chmod og+r CA.key
  chmod og+r CA.crt

  echo -e "${GREEN}Certificates are ready: ${NC}"
  echo -e "\t${GREEN}Server Certificate: ${RED}server.crt${NC}"
  echo -e "\t${GREEN}Server Key        : ${RED}server.key${NC}"
  echo -e "\t${GREEN}PKCS12 Keystore   : ${RED}${KEYSTORE_FILE}${NC}"
  echo -e "\t${GREEN}CA Certificate    : ${RED}CA.crt${NC}"
  echo -e "\t${GREEN}CA Key            : ${RED}CA.key${NC}"
popd