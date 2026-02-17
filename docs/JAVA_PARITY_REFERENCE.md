# Referencia de Paridad Java (clienteafirma-master)

Fecha: 2026-02-17  
Origen revisado: `/home/alberto/Trabajo/Autofirma-go/clienteafirma-master`

## Clases Java revisadas
- `afirma-simple/.../ProtocolInvocationLauncher.java`
- `afirma-simple/.../AfirmaWebSocketServerV4.java`
- `afirma-simple/.../ProtocolInvocationLauncherBatch.java`
- `afirma-simple/.../IntermediateServerUtil.java`
- `afirma-simple/.../ProtocolInvocationLauncherErrorManager.java`
- `afirma-ui-miniapplet-deploy/.../autoscript.js`

## Comportamiento observado en Java

1. Operaciones `afirma://` soportadas por launcher
- `websocket`
- `service`
- `batch`
- `selectcert`
- `save`
- `signandsave`
- `sign`, `cosign`, `countersign`
- `load`

2. Canal WebSocket v4
- Acepta solo loopback (`127.0.0.1`).
- Valida `idsession` en cada mensaje.
- Responde `OK` a `echo=...@EOF`.
- Si es batch, amplía timeout de conexión perdida.
- Procesa la URI con `ProtocolInvocationLauncher.launch(..., bySocket=true)`.

3. Formato de errores
- En canal WebSocket/protocolo devuelve familia `SAF_xx`.
- En endpoints de servidor intermedio (`StorageService`/`RetrieveService`) usa familia `ERR-xx:=...`.

4. Servidor intermedio
- `sendData`: `POST` con query `?op=put&v=1_0&id=...&dat=...`.
- `retrieveData`: `POST` con query `?op=get&v=1_0&id=...`.

5. Lotes (`batch`)
- Soporta JSON/XML.
- Soporta firma local y trifásica (`batchpresignerurl`/`batchpostsignerurl`).
- Puede devolver resultado + certificado (`result|cert`).

## Impacto directo en Go (estado actual)

- Alineado:
  - Errores WebSocket con prefijo `SAF_` (no `ERR`).
  - Validación de `idsession` en mensajes WSS.
  - Restricción de origen loopback en WSS/service.
  - `StorageService`/`RetrieveService` siguen formato `ERR-xx:=...`.
  - Operaciones `selectcert`, `save`, `signandsave`, `load` soportadas en flujo WSS (con cobertura de aliases y cancelación).
  - Operaciones `sign`, `cosign`, `countersign` soportadas en flujo protocolario.
  - `batch` local JSON/XML y trifásico remoto JSON/XML implementados en modo funcional.
  - Validación de versión mínima de cliente (`mcv`) en protocolo con error `SAF_41` cuando no se satisface.
  - Tratamiento tolerante de versión de JavaScript (`jvc`) sin bloqueo de operación (aviso por log).
  - Validación de versión de protocolo en lanzamiento:
    - `afirma://websocket` con control de versiones soportadas (3/4).
    - `afirma://service` con control de versiones soportadas (1/2/3).
    - devolución `SAF_21` cuando se solicita una versión no soportada.
- Pendiente:
  - Afinado final de casuística trifásica remota `batch` contra sedes reales.
  - Validación E2E del canal `service` legacy en sedes reales (sin brecha funcional abierta en código unitario).
  - Paridad completa de filtros avanzados de `selectcert` y apertura de almacenes externos por UI.
  - Paridad avanzada de firma (CAdES/PAdES/XAdES más allá del baseline).

## Criterio de implementación recomendado
- Implementar cada operación nueva en Go con:
  - parser de URI dedicado,
  - test de compatibilidad (entrada/salida),
  - mapeo explícito de errores Java (`SAF_xx`),
  - evidencia en `AVANCES_PARIDAD_JAVA_GO.md`.
