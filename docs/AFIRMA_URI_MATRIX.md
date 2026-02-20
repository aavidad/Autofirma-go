# Matriz Base de Compatibilidad `afirma://`

Licencia: GPLv3.
Autor: Alberto Avidad Fernandez.
Organizacion: Oficina de Software Libre de la Diputacion de Granada.

Estado: en construcción (P1)  
Fecha: 2026-02-16

## Objetivo
Tener una matriz explícita de variantes de URI y comportamiento esperado para comparar Go vs Java y cubrir regresiones.

## Variantes cubiertas (actual)

1. `afirma://sign?fileid=...&rtservlet=...&stservlet=...`
- Estado Go: soportado.
- Notas: flujo remoto estándar.

2. `afirma://sign?id=...&retrieveservlet=...&storageservlet=...`
- Estado Go: soportado.
- Notas: alias de parámetros.

2.1 Variantes legacy de acción/esquema
- Estado Go: soportado.
- Notas:
  - acción en path: `afirma:///sign?...`, `afirma:///websocket?...`
  - acción en query fallback: `afirma://?op=sign...`, `afirma://?operation=websocket...`
  - esquema case-insensitive: `AFIRMA://...`
  - alias de acción:
    - `firmar` -> `sign`
    - `cofirmar` -> `cosign`
    - `contrafirmar[_arbol|_hojas]` -> `countersign`
  - alias de parámetros con tolerancia de mayúsculas/minúsculas:
    - `fileid/id/fileId/requestId`
    - `rtservlet/retrieveservlet/rtServlet/retrieveServlet`
    - `stservlet/storageservlet/stServlet/storageServlet`
    - `format/signFormat`
    - `idsession/idSession`
    - `ports/port/portsList`

3. `afirma://sign?id=...&stservlet=...` (sin `rtservlet`)
- Estado Go: soportado.
- Notas: flujo de selección manual de fichero local.

4. `afirma://sign` sin `id/rtservlet/stservlet`
- Estado Go: rechazado con error de parámetros insuficientes.

5. `afirma://websocket?...`
- Estado Go: soportado.
- En canal WSS responde `OK` y valida `ports` cuando se proporcionan.

6. `afirma://batch?...`
- Estado Go: parcial.
- Soportado:
  - lote local JSON (`jsonbatch=true` + `localBatchProcess=true`)
  - lote local XML (`jsonbatch` ausente/false + `localBatchProcess=true`)
  - parseo de `dat` (o descarga por servlet), selección de certificado única, procesado `singlesigns`
  - `datareference/datasource` en batch local:
    - Base64
    - rutas locales
    - `file://`
  - `stoponerror` con estados compatibles (`DONE_AND_SAVED`, `ERROR_PRE`, `SKIPPED`)
  - salida:
    - JSON -> log JSON de resultados
    - XML -> log XML `<signs><signresult .../></signs>`
    - en ambos: Base64 estándar (cifrada si hay `key`) y `needcert` opcional
  - lote trifásico remoto (`localBatchProcess=false`):
    - JSON y XML soportados con flujo `pre -> PK1 cliente -> post`
    - `tridata` JSON/XML firmado en cliente Go y enviado en `post`
- Pendiente:
  - afinado final de casuística remota trifásica frente a sedes concretas

7. `afirma://cosign?...` / `afirma://countersign?...`
- Estado Go: parcial.
- Notas: enruta al flujo interactivo de firma actual.

7.1 `suboperation` en `batch` local (JSON/XML)
- Estado Go: parcial avanzado.
- Soportado:
  - resolución de operación por lote (`signbatch.suboperation` / raíz JSON) y por elemento (`singlesign.suboperation`)
  - prioridad: operación por elemento sobre la global
  - alias compatibles: `sign|firmar`, `cosign|cofirmar`, `countersign|contrafirmar|contrafirmar_arbol|contrafirmar_hojas`
  - cofirma local CAdES (best-effort) en backend Go
  - contrafirma local CAdES real en backend Go (CMS `counterSignature`, OID `1.2.840.113549.1.9.6`)
  - `target` de contrafirma soportado en CAdES:
    - `leafs` (por defecto)
    - `tree`
    - `signers` (con selección en `targets`/`signers`)
- Nota de paridad Java:
  - en la ruta protocolaria Java actual, `target` efectivo se resuelve en práctica a `tree` o `leafs`.
  - `nodes/signers` pertenecen al motor criptográfico histórico y no son usados por defecto en la invocación protocolaria estándar.

8. `afirma://selectcert?...`, `afirma://save?...`, `afirma://signandsave?...`, `afirma://load?...`
- Estado Go: parcial.
- `selectcert`: soportado con diálogo interactivo (si hay UI), cancelación (`CANCEL`) y soporte `sticky/resetsticky`; con `key` cifra respuesta.
  - Soporte de `properties` en base64 para filtros de certificado y modo auto-selección.
  - Filtros implementados en Go (paridad parcial con Java): `filter`/`filters`/`filters.N`, `subject.contains`, `issuer.contains`, `subject.rfc2254`, `issuer.rfc2254`, `issuer.rfc2254.recurse` (best-effort sobre emisor directo), `nonexpired`, `signingcert` (basado en `nonRepudiation/contentCommitment`), `thumbprint`, `encodedcert`, `policyid`, `keyusage.*`, `pseudonym:only`, `pseudonym:andothers` (oculta certificado normal equivalente), `dnie`, `authcert`, `qualified` (serial + emparejado por emisor/SN/caducidad), `ssl` (serial + emparejado por emisor/SN/caducidad), `sscd`.
  - Auto-selección sin diálogo cuando `headless=true` o `mandatoryCertSelection=false`.
- `save`: soportado con diálogo de guardado (si hay UI), cancelación (`CANCEL`) y respuesta `SAVE_OK`.
- `load`: soportado con `filePath` o diálogo interactivo (si hay UI), con soporte de múltiple (`multiload`) y cancelación (`CANCEL`).
  - Con UI sigue comportamiento Java: se abre diálogo siempre, usando `filePath/filepath` como ruta inicial cuando se proporciona.
- `signandsave`: soportado en mínimo funcional (firma interactiva + guardado en `~/Descargas`, responde `SAVE_OK`).
- `sign` (flujo WSS/protocolo):
  - soporte parcial de `properties` aplicado a firma:
    - metadatos PAdES (`signReason`, `signatureProductionCity`, `signerContact`, `tsaURL`)
    - geometría visible (`signaturePage`, `signaturePositionOnPageLowerLeftX/Y`, `signaturePositionOnPageUpperRightX/Y`)
    - algoritmo de firma (`algorithm`) propagado a digest real en CAdES/PAdES
    - expansión de política AGE vía `expPolicy` (`FirmaAGE`, `FirmaAGE19`, `FirmaAGE18`) a `policyIdentifier*`
  - parámetros directos de la petición tienen prioridad sobre `properties`.
- Nota de paridad Java: Java combina salidas `OK`/`SAVE_OK` según canal; en Go se mantiene `SAVE_OK` en `save/signandsave` para compatibilidad web.

9. `afirma://service?...`
- Estado Go: parcial (avanzado).
- Soportado:
  - arranque de servidor socket TLS legado en los `ports` solicitados
  - integración de `idsession`
  - comandos de protocolo legado en socket:
    - `echo=`
    - `cmd=`
    - `fragment=`
    - `firm=`
    - `send=`
  - respuesta HTTP con payload en Base64 URL-safe (estilo Java)
- Pendiente:
  - paridad fina de framing/tiempos y casuística completa del `CommandProcessorThread` Java
- Compatibilidad adicional ya aplicada:
  - parseo robusto de `idsession/idSession` en canal legacy.
  - `cmd/fragment/send` robustos cuando el sufijo llega como `idSession=...@EOF`.
  - validación de origen local acepta `localhost`, `127.0.0.1` y `::1`.

## Formato de error de protocolo (canal WSS)
- Se normaliza a familia Java `SAF_xx: mensaje`
- Mapeo implementado:
  - Protocolo inválido -> `SAF_02`
  - Parseo URI -> `SAF_03`
  - Descarga/comunicación -> `SAF_16`
  - Guardado -> `SAF_05`
  - Construcción de respuesta -> `SAF_12`
  - Operación no soportada -> `SAF_04`
  - UI de firma no disponible -> `SAF_09`
  - Acceso a almacén -> `SAF_08`
  - Sin certificados sistema/almacén -> `SAF_10`/`SAF_19`
  - Lote local/remoto -> `SAF_20`/`SAF_26`/`SAF_27`
  - Apertura socket/idsession/origen externo -> `SAF_45`/`SAF_46`/`SAF_47`
  - Resto -> `SAF_03`

## Próximos casos a añadir
- Variantes de batch usadas por sedes reales (XML/trifásico).
- Casos con `key` y cifrado en ida/vuelta.
- Casos con XML `<sign>` con combinaciones de parámetros heredados.
