#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}🔐 AutoFirma Native Host - Certificate Installer${NC}"
echo "This script will generate a local Root CA and a server certificate for 127.0.0.1,"
echo "and install the CA into your browser's trust store."

# 1. Clean up old files
echo "Cleaning up old certificates..."
rm -f rootCA.key rootCA.crt server.key server.csr server.crt

# 2. Generate Root CA
echo "Generating Root CA..."
openssl genrsa -out rootCA.key 2048
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 3650 -out rootCA.crt -subj "/C=ES/ST=Granada/L=Granada/O=AutoFirma Dev/CN=AutoFirma Dev Root CA"

# 3. Generate Server Key
echo "Generating Server Key..."
openssl genrsa -out server.key 2048

# 4. Generate CSR (Certificate Signing Request)
echo "Generating CSR..."
openssl req -new -key server.key -out server.csr -subj "/C=ES/ST=Granada/L=Granada/O=AutoFirma Dev/CN=127.0.0.1"

# 5. Create config for Subject Alternative Name (SAN)
cat > server.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
IP.1 = 127.0.0.1
DNS.1 = localhost
EOF

# 6. Sign the CSR with Root CA
echo "Signing Server Certificate..."
openssl x509 -req -in server.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out server.crt -days 3650 -sha256 -extfile server.ext

rm server.csr server.ext rootCA.srl

echo -e "${GREEN}✅ Certificates generated.${NC}"

# 7. Install into NSS Database (Chrome, Chromium, Edge on Linux)
if command -v certutil &> /dev/null; then
    echo "Installing CA into NSS Database (Chrome/Chromium)..."
    
    # User's NSS DB
    NSSDB="$HOME/.pki/nssdb"
    if [ -d "$NSSDB" ]; then
        certutil -d sql:"$NSSDB" -A -t "C,," -n "AutoFirma Dev Root CA" -i rootCA.crt
        echo -e "${GREEN}✅ Added to Chrome/Chromium trust store.${NC}"
    else
        echo -e "${RED}⚠️  NSS DB not found at $NSSDB${NC}"
    fi

    # Firefox Profiles
    echo "Checking Firefox profiles..."
    for certDB in $(find "$HOME/.mozilla/firefox" -name "cert9.db"); do
        certDir=$(dirname "$certDB")
        echo "Adding to Firefox profile: $certDir"
        certutil -d sql:"$certDir" -A -t "C,," -n "AutoFirma Dev Root CA" -i rootCA.crt
        echo -e "${GREEN}✅ Added to Firefox profile.${NC}"
    done
else
    echo -e "${RED}❌ 'certutil' is not installed. Skipping browser registration.${NC}"
    echo "Please install 'libnss3-tools' (Debian/Ubuntu) or 'nss-tools' (Fedora/Arch)."
fi

# 8. Copy to dist
mkdir -p dist
cp server.crt dist/
cp server.key dist/

echo ""
echo -e "${GREEN}🎉 Done!${NC}"
echo "1. Restart your browser."
echo "2. Run the application: ./dist/autofirma-desktop --server"
echo "3. The browser should now trust wss://127.0.0.1:63117/ automatically."
