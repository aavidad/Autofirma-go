# Modo compatibilidad web (sedes oficiales)

Licencia: GPLv3.
Autor: Alberto Avidad Fernandez.
Organizacion: Oficina de Software Libre de la Diputacion de Granada.

Directorio de trabajo aislado:
- `/home/alberto/Trabajo/GrxGo/.codex_workspace/autofirma_migracion/work/native-host-src`

## 1) Arrancar servidor WebSocket seguro local
```bash
cd /home/alberto/Trabajo/GrxGo/.codex_workspace/autofirma_migracion/work/native-host-src
./autofirma-desktop --generate-certs
./autofirma-desktop --install-trust
./autofirma-desktop --trust-status
./scripts/run_web_compat_server.sh start
./scripts/run_web_compat_server.sh status
```

## 2) Verificar handshake+echo WSS
```bash
./scripts/ws_echo_client.py
```
Esperado: `OK`

## 3) Probar en TestAutoFirma
URL:
- `https://www.sededgsfp.gob.es/es/Paginas/TestAutofirma.aspx`

Pasos:
1. Tener el servidor en marcha.
2. Abrir la URL en navegador.
3. Si el navegador bloquea el certificado local, abrir una vez:
   - `https://127.0.0.1:63117/`
   y aceptar excepción de certificado (solo si `--trust-status` no aparece como `OK`).
4. Inyectar `scripts/inject_webservice_compat.js` en consola del navegador.
5. Pulsar "Firmar" y revisar respuesta.

## 3.1) Qué se está clonando del Java oficial
- `GET .../StorageService?op=check` => `200 OK` + `OK`
- `GET .../RetrieveService?op=check` => `200 OK` + `OK`
- `POST .../StorageService` con `op=put&v=1_0&id=...&dat=...` => `OK`
- `GET .../RetrieveService?op=get&v=1_0&id=...` => dato o `ERR-06:=...` (polling)

## 4) Logs
- `/tmp/autofirma-web-compat.log`

```bash
tail -f /tmp/autofirma-web-compat.log
```

## 5) Parar servidor
```bash
./scripts/run_web_compat_server.sh stop
```

## 6) Flujo E2E guiado (Valide + segunda sede)
```bash
cd /home/alberto/Trabajo/Autofirma-go
./scripts/run_sede_e2e.sh start --clean-logs
```

Tras ejecutar manualmente la firma en las sedes:
```bash
./scripts/run_sede_e2e.sh check --since-minutes 240
./scripts/run_sede_e2e.sh stop
```

Validación específica de contrafirma XAdES (interoperabilidad real):
```bash
./scripts/run_sede_e2e.sh check --since-minutes 240 --require-xades-countersign
```
Esperado:
- `result: PASS` en el reporte generado (`/tmp/autofirma-sede-e2e-report-*.txt`).
- `xades_countersign_evidence_seen: 1`.
- Sin `SAF_03`, `ERR-*` ni errores de ruta XAdES.

## 7) Ajustes por sede (red inestable / servicios lentos)
Variables de entorno disponibles para lote trifásico remoto:

```bash
# Timeout HTTP de prefirma/postfirma (elige una)
export AUTOFIRMA_BATCH_HTTP_TIMEOUT_MS=30000
# o
export AUTOFIRMA_BATCH_HTTP_TIMEOUT_SEC=30

# Reintentos HTTP transitorios (default 3, max 6)
export AUTOFIRMA_BATCH_HTTP_MAX_ATTEMPTS=5

# Circuit breaker por host remoto
# Se abre tras N fallos consecutivos (default 3, max 10)
export AUTOFIRMA_BATCH_BREAKER_THRESHOLD=4
# Cooldown del breaker (default 20s, max 5m)
export AUTOFIRMA_BATCH_BREAKER_COOLDOWN_SEC=45
```

Aplicar y ejecutar E2E:
```bash
./scripts/run_sede_e2e.sh start --clean-logs
```

## Notas
- Esta validación comprueba compatibilidad de canal (`wss://127.0.0.1:63117`) y protocolo básico.
- El resultado final en web oficial depende también del flujo exacto de `afirma://...` que emita AutoScript en esa sesión.
