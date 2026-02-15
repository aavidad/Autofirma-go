# Control de `afirma://` en modo local

Sí, se puede controlar el flujo `afirma://` en este entorno aislado.

## 1) Arrancar servidor de compatibilidad
```bash
cd /home/alberto/Trabajo/GrxGo/.codex_workspace/autofirma_migracion/work/native-host-src
./scripts/run_web_compat_server.sh start
```

## 2) Comprobar canal WSS
```bash
./scripts/ws_echo_client.py
```
Debe responder `OK`.

## 3) Enviar URI `afirma://` manualmente
```bash
./scripts/ws_send_afirma_uri.py 'afirma://sign?fileid=...&rtservlet=...&key=...'
```

Resultado esperado:
- Respuesta tipo `certBase64|signatureBase64`
- O error `ERR-...` si faltan parámetros/datos.

## 4) Interceptar en navegador (test oficial)
- Abre `https://www.sededgsfp.gob.es/es/Paginas/TestAutofirma.aspx`
- Inyecta `interceptor-autofirma.js` en consola.
- El interceptor captura clics `afirma://...` y los envía al WSS local.

## 5) Diagnóstico
```bash
tail -f /tmp/autofirma-web-compat.log
```

## Notas técnicas
- El servidor actual acepta origen abierto (`CheckOrigin=true`) para maximizar compatibilidad de pruebas.
- El handling de `afirma://` se ejecuta en `cmd/gui/websocket.go` (`processProtocolRequest`).
