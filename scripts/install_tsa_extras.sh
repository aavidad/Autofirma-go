#!/bin/bash
# scripts/install_tsa_extras.sh
# Descarga e instala certificados raíz de autoridades de sellado de tiempo comunes (TSA) en España.

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}📥 Iniciando descarga de certificados TSA (Camerfirma y otros)...${NC}"

# URLs de certificados TSA y Raíces de Administraciones Públicas (Camerfirma, FNMT, ACCV, etc.)
CERTS=(
  "https://www.camerfirma.com/wp-content/uploads/2021/06/AC_CAMERFIRMA_TSA-2016.crt"
  "https://www.camerfirma.com/wp-content/uploads/2021/06/Camerfirma_TSA_II-2014.crt"
  "https://www.camerfirma.com/wp-content/uploads/2021/06/AC_CAMERFIRMA_TSU-2022.crt"
  "https://www.camerfirma.com/wp-content/uploads/2021/06/Camerfirma_Root_CA.cer"
  "https://www.cert.fnmt.es/documents/104459/434351/AC_Raiz_FNMT-RCM_SHA256.cer"
  "https://www.accv.es/wp-content/uploads/cert/accv_raiz1.crt"
)

mkdir -p /tmp/autofirma_tsa_certs
cd /tmp/autofirma_tsa_certs

for url in "${CERTS[@]}"; do
    filename=$(basename "$url")
    echo "Descargando: $filename..."
    curl -s -L "$url" -o "$filename" || echo -e "${RED}⚠️ No se pudo descargar $filename${NC}"
done

# Instalación en almacenes NSS (Navegadores Chrome/Firefox)
if command -v certutil &> /dev/null; then
    echo "Instalando en almacenes de certificados NSS..."
    for cert in *.crt *.cer; do
        [ -e "$cert" ] || continue
        # Chrome/Chromium
        NSSDB="$HOME/.pki/nssdb"
        if [ -d "$NSSDB" ]; then
            certutil -d sql:"$NSSDB" -A -t "C,," -n "AutoFirma TSA - $(basename "$cert")" -i "$cert" 2>/dev/null || true
        fi
        # Firefox
        for certDB in $(find "$HOME/.mozilla/firefox" -name "cert9.db" 2>/dev/null); do
            certDir=$(dirname "$certDB")
            certutil -d sql:"$certDir" -A -t "C,," -n "AutoFirma TSA - $(basename "$cert")" -i "$cert" 2>/dev/null || true
        done
    done
    echo -e "${GREEN}✅ Instalación en navegadores completada.${NC}"
else
    echo -e "${RED}❌ 'certutil' no está instalado. No se pudo registrar en navegadores.${NC}"
fi

# Nota: Para el almacén del sistema Linux se requiere sudo. 
# En este entorno de usuario, nos aseguramos de que estén disponibles para el backend.

echo ""
echo -e "${GREEN}🎉 Proceso finalizado.${NC}"
