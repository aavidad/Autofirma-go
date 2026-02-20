# AutoFirma Dipgra REST API

API local para exponer las funciones principales de AutoFirma sin UI (firma, verificación, certificados, diagnóstico y seguridad).

## Arranque

```bash
autofirma-desktop -rest -rest-addr 127.0.0.1:63118 -rest-token secreto
# Alias en castellano:
autofirma-desktop -servidor-rest -direccion-rest 127.0.0.1:63118 -token-rest secreto
```

También puede usarse autenticación por certificado:

```bash
autofirma-desktop -rest -rest-addr 127.0.0.1:63118 -rest-cert-fingerprints <sha256,sha256> -rest-session-ttl 10m
# Alias en castellano:
autofirma-desktop -servidor-rest -huellas-cert-rest <sha256,sha256> -ttl-sesion-rest 10m
```

## Autenticación

Opciones soportadas:

1. Token fijo (`-rest-token`):

```http
Authorization: Bearer <token>
```

2. Sesión por certificado (challenge/verify):

1) `GET /auth/challenge` (o `POST /auth/challenge`) devuelve `challengeId` + `challengeB64`.
2) El cliente firma `challengeB64` con su certificado.
3) `POST /auth/verify` enviando `challengeId`, `signatureB64` y `certificatePEM` (o `certificateB64`).
   También admite alias en castellano: `idReto`, `firmaB64`, `certificadoPEM`, `certificadoB64`.
4) Respuesta con `sessionToken` (usar como Bearer en endpoints protegidos).

## Endpoints

### Públicos

- `GET /`
  - Consola web integrada para operar la API.

- `GET|POST /auth/challenge`
  - Genera reto temporal para login con certificado.
  - Alias en castellano: `GET|POST /autenticacion/reto`.

- `POST /auth/verify`
  - Verifica firma del reto y emite sesión temporal.
  - Alias en castellano: `POST /autenticacion/verificar`.

### Protegidos

- `GET /health`
  - Estado de servicio y versión.
  - Alias en castellano: `GET /salud`.

- `GET /certificates?check=0|1`
  - Lista certificados disponibles.
  - `check=1` fuerza prueba de capacidad de firma.
  - Alias en castellano: `GET /certificados?comprobar=0|1`.

- `POST /sign`
  - Firma local.
  - Alias en castellano: `POST /firmar`.
  - Campos principales:
    - `inputPath`, `outputPath`
    - `action`: `sign|cosign|countersign`
    - `format`: `auto|pades|cades|xades`
    - selector de certificado: `certificateId` o `certificateIndex` o `certificateContains`
    - `overwrite`: `rename|fail|force`
    - `saveToDisk`, `returnSignatureB64`, `strictCompat`, `allowInvalidPDF`
    - `visibleSeal` (PAdES): `page,x,y,w,h` en coordenadas normalizadas (0..1)
  - Alias de campos en castellano admitidos:
    - `rutaEntrada`, `rutaSalida`
    - `accion`, `formato`
    - `idCertificado`, `indiceCertificado`, `certificadoContiene`
    - `sobrescribir`, `guardarEnDisco`, `devolverFirmaB64`, `compatibilidadEstricta`, `permitirPDFInvalido`
    - `selloVisible`

- `POST /verify`
  - Verifica firma local.
  - Alias en castellano: `POST /verificar`.
  - Modos:
    - Acoplado (ej. PAdES): `inputPath`
    - Desacoplado (ej. CAdES): `signaturePath` y opcional `originalPath`
  - Alias de campos en castellano admitidos:
    - `rutaEntrada`, `rutaFirma`, `rutaOriginal`, `formato`.

- `GET /diagnostics/report`
  - Reporte JSON resumido:
    - versión, timestamp
    - certificados detectados y válidos para firma
    - dominios de confianza
    - estado del almacén TLS local de endpoints
    - estado de confianza TLS local
    - estado de auth REST (token/cert)
  - Alias en castellano: `GET /diagnostico/informe`.

- `GET /security/domains`
  - Lista dominios de firma confiados.
  - Alias en castellano: `GET /seguridad/dominios`.

- `POST /security/domains`
  - Añade dominio confiado.
  - Body: `{ "domain": "firma.ejemplo.gob.es" }`
  - Alias en castellano: `POST /seguridad/dominios` con body `{ "dominio": "firma.ejemplo.gob.es" }`.

- `DELETE /security/domains`
  - Elimina dominio confiado.
  - Body: `{ "domain": "firma.ejemplo.gob.es" }`
  - Alias en castellano: `DELETE /seguridad/dominios` con body `{ "dominio": "firma.ejemplo.gob.es" }`.

- `POST /tls/clear-store`
  - Limpia certificados TLS de endpoints guardados en truststore local de AutoFirma.
  - Alias en castellano: `POST /tls/limpiar-almacen`.

- `GET /tls/trust-status`
  - Devuelve el estado de confianza TLS local (NSS/sistema/keychain según SO) y el estado del store local de endpoints.
  - Alias en castellano: `GET /tls/estado-confianza`.

- `POST /tls/install-trust`
  - Ejecuta instalación de confianza TLS local (equivalente a `-install-trust`).
  - Puede requerir permisos elevados en algunos sistemas.
  - Alias en castellano: `POST /tls/instalar-confianza`.

- `POST /tls/generate-certs`
  - Genera/asegura certificados TLS locales (equivalente a `-generate-certs`).
  - Alias en castellano: `POST /tls/generar-certificados`.

## Ejemplos curl

```bash
# Health con token
curl -H 'Authorization: Bearer secreto' http://127.0.0.1:63118/health

# Certificados
curl -H 'Authorization: Bearer secreto' 'http://127.0.0.1:63118/certificates?check=1'

# Diagnóstico completo
curl -H 'Authorization: Bearer secreto' http://127.0.0.1:63118/diagnostics/report

# Añadir dominio confiado
curl -X POST -H 'Authorization: Bearer secreto' -H 'Content-Type: application/json' \
  -d '{"domain":"firma.ejemplo.gob.es"}' \
  http://127.0.0.1:63118/security/domains

# Borrar dominio confiado
curl -X DELETE -H 'Authorization: Bearer secreto' -H 'Content-Type: application/json' \
  -d '{"domain":"firma.ejemplo.gob.es"}' \
  http://127.0.0.1:63118/security/domains

# Limpiar truststore de endpoints
curl -X POST -H 'Authorization: Bearer secreto' http://127.0.0.1:63118/tls/clear-store

# Estado de confianza TLS
curl -H 'Authorization: Bearer secreto' http://127.0.0.1:63118/tls/trust-status

# Generar certificados TLS locales
curl -X POST -H 'Authorization: Bearer secreto' http://127.0.0.1:63118/tls/generate-certs
```

## Notas de seguridad

- Bind por defecto en loopback (`127.0.0.1`).
- No exponer esta API en interfaces públicas.
- Usar siempre `-rest-token` y/o login por certificado con lista blanca (`-rest-cert-fingerprints`) en entornos sensibles.
