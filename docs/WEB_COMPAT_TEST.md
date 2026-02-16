# Modo compatibilidad web (sedes oficiales)

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

## Notas
- Esta validación comprueba compatibilidad de canal (`wss://127.0.0.1:63117`) y protocolo básico.
- El resultado final en web oficial depende también del flujo exacto de `afirma://...` que emita AutoScript en esa sesión.
