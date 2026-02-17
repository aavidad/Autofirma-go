# Seguimiento Diario de Paridad Java -> Go

## Regla de uso
- En cada sesión, anotar:
  - `Hecho hoy`
  - `Pendiente`
  - `Siguiente paso inmediato`
- No incluir secretos (PIN, payloads completos, claves privadas).

## 2026-02-17 10:39 +0100
### Hecho hoy
- Paridad `mcv/jvc` implementada:
  - `mcv` valida versión mínima cliente y devuelve `SAF_41` si no se cumple.
  - `jvc` se parsea en modo tolerante y genera aviso de log si es inseguro.
- Paridad `aw` corregida:
  - el envío de `#WAIT` solo se activa con `aw=true`.
- Paridad de versión de protocolo en lanzadores:
  - `service` valida `v` (1/2/3) y `websocket` valida `v` (3/4).
  - versión no soportada devuelve `SAF_21`.
  - fallback compat cuando no llega `v`: `service=3`, `websocket=4`.
- Paridad de versión de protocolo en operaciones:
  - en `afirma://sign/...` se valida `v` y fuera de rango se devuelve `SAF_21`.
  - rango soportado en launcher protocolario: `0..4`.
- Paridad de respuesta de firma v3+:
  - soporte de `extraInfo` en tercer campo de respuesta (`cert|sign|extra`) para protocolo `v>=3`.
  - `extraInfo` inicial enviado: JSON con `filename`.
- Lanzamiento `afirma://websocket` reforzado:
  - parseo robusto con aliases (`port/portsList`, `idSession`) y esquema case-insensitive.
  - validación de versión websocket soportada (`3/4`) en arranque por URI.
  - fallback de puertos: usa `63117` cuando no viene `ports`.
  - detección de launch en `main` alineada con parser (soporta también `op=websocket`).
- `jvc` en launch `service/websocket`: avisa en log si es inseguro, sin bloquear.
  - tests unitarios nuevos para parser de launch URI.
- `service` legacy hereda versión de protocolo hacia `cmd/firm` cuando la URI no trae `v`:
  - mejora coherencia de versión en el flujo socket legacy.
  - no se fuerza `v` en URIs de launch (`afirma://websocket`/`afirma://service`).
- `service` legacy con `idsession` inválido:
  - ajustado a `SAF_03` (paridad Java `CommandProcessorThread`).
  - `SAF_46` se conserva para el canal WebSocket.
- `service` legacy: payload totalmente URL-encoded:
  - normalización previa al parseo (`cmd%3D...`) para compatibilidad con intermediarios/proxies.
  - ampliado a payload doblemente URL-encoded (`cmd%253D...`).
- `service` legacy: parseo HTTP más robusto:
  - delimitación por `" HTTP/"` en lugar de cortar por espacio suelto, para no truncar valores con espacios internos.
- `service` legacy: fragmentos fuera de orden:
  - ahora se rechazan con `SAF_03` (paridad con comportamiento Java al insertar con índice).
- Mejora Go (más robusta que Java) en `service` legacy:
  - límite de tamaño de payload fragmentado (32 MiB por defecto), con `MEMORY_ERROR` + limpieza de estado al exceder.
- Mejora Go adicional en `service` legacy:
  - límite de tamaño de request cruda de socket (8 MiB por defecto), con `MEMORY_ERROR` al exceder.
  - validado también a nivel de handler de conexión (`handleLegacyServiceConn`) con test de respuesta HTTP codificada.
- Ajuste de paridad Java en errores de lectura de `service` legacy:
  - si falla la lectura del socket, ahora se devuelve `SAF_03` (antes se ignoraba sin respuesta).
- Ajuste de paridad en `selectcert`:
  - `mandatoryCertSelection=false` ya no fuerza auto-selección con múltiples candidatos.
  - ahora solo omite diálogo cuando tras filtros queda un único certificado (alineado con Java).
  - parseo de `properties` en query robusto a mayúsculas/minúsculas (`properties`/`Properties`).
  - parseo de claves dentro de `properties` también robusto a mayúsculas/minúsculas (`filter`, `filters`, `headless`, `mandatoryCertSelection`).
  - `nonexpired` ahora valida con fechas X.509 cuando faltan `ValidFrom/ValidTo` en el modelo de certificado.
  - compatibilidad de versión legacy ampliada: se acepta `ver` como alias de `v`.
  - soporte best-effort de `defaultKeyStore` en `selectcert` con fallback seguro:
    - `PKCS11` prioriza `smartcard/dnie`.
    - `MOZ_UNI/SHARED_NSS/MOZILLA` prioriza `system`.
    - `WINDOWS/WINADDRESSBOOK` prioriza `windows`.
    - `APPLE/MACOS/KEYCHAIN` prioriza `system`.
  - el mismo criterio de `defaultKeyStore` se aplica ya también en selección de certificado de `batch`.
  - en `batch`, lectura de `sticky/resetsticky` alineada con parser robusto (case-insensitive + aliases).
  - `batch` alineado con auto-selección de `selectcert`: en headless con candidato único puede operar sin UI.
  - soporte de `defaultKeyStoreLib` para `PKCS11` en carga de certificados:
    - cuando llega en la invocación, se usa como hint de módulo PKCS#11 (también en `batch` al compartir el loader).
    - sin hint, se mantiene flujo previo sin cambios.
    - si falla el loader con hints, fallback automático al loader por defecto (sin romper flujo).
    - trazas de diagnóstico adicionales para soporte:
      - resumen de módulos/hints y recuento de certificados del loader con opciones.
  - optimización adicional por `defaultKeyStore`:
    - cuando el store pedido no es PKCS#11, se omite escaneo PKCS#11 para evitar latencia/prompts innecesarios.
    - para stores desconocidos se mantiene comportamiento conservador (loader por defecto).
  - si `defaultKeyStore=PKCS11` con `defaultKeyStoreLib` no devuelve certs de token, reintenta con descubrimiento PKCS#11 por defecto.
  - `disableopeningexternalstores` ahora afecta a la carga:
    - sin `defaultKeyStore=PKCS11` explícito, desactiva escaneo PKCS#11.
    - con `defaultKeyStore=PKCS11` explícito, se respeta la preferencia PKCS#11.
- Documentación de paridad actualizada:
  - `AVANCES_PARIDAD_JAVA_GO.md`
  - `docs/JAVA_PARITY_REFERENCE.md`

### Pendiente
- E2E en sedes reales (Valide + otra sede) y revisión de logs sin `SAF_03/ERR-*` no esperados.
- Afinado final de casuística batch trifásico remoto contra sedes reales.
- Paridad fina de `service` legacy en casos límite restantes.
- Paridad avanzada de `selectcert` con almacenes/proveedores reales.

### Siguiente paso inmediato
- Continuar con revisión funcional frente a Java por bloques y cerrar siguiente brecha de `service` legacy o `selectcert` avanzado.

### Nuevo avance (2026-02-17, continuidad bloque grande)
- Firma y selección de almacén más coherentes:
  - `buildProtocolSignOptions` propaga al firmador `_defaultKeyStore`, `_defaultKeyStoreLib` y `_disableOpeningExternalStores`.
  - `pkg/signer` usa esas pistas para cargar certificados con opciones de almacén (igual criterio que `selectcert`) y fallback al loader por defecto ante error.
- Fallback de `nickname` en firma:
  - si el cert resuelto para firmar no trae `nickname`, se busca certificado equivalente con nickname en la carga por defecto para evitar fallos evitables.
- Cobertura añadida:
  - `TestBuildProtocolSignOptionsPropagatesStoreHintsForSigner`
  - `TestGetCertificateByIDUsesStoreOptionsForLookup`
  - `TestGetCertificateByIDFallsBackToNicknameCertificate`
  - `TestResolveCertstoreOptionsPKCS11Hints`

### Nuevo avance (2026-02-17, selectcert thumbprint)
- Ajustada paridad de `thumbprint` con Java:
  - formato Java soportado: `thumbprint:<algoritmo>:<huellaHex>`.
  - se conserva formato legacy previo en Go para no romper integraciones.
  - soporte digest ampliado en filtro: `SHA-384` y `SHA-512`.
- Cobertura añadida:
  - `TestThumbprintFilterSupportsJavaAlgorithmFirstFormat`
  - `TestThumbprintFilterKeepsBackwardCompatibilityHexFirst`

### Nuevo avance (2026-02-17, selectcert keyusage)
- Ajuste de paridad Java en `keyusage.*`:
  - `keyusage.<uso>:null` ahora se interpreta como “sin restricción” (antes podía forzar `false`).
- Cobertura añadida:
  - `TestMatchesKeyUsage` ampliado con caso `keyusage.keyencipherment:null`.

### Nuevo avance (2026-02-17, selectcert signingcert + batch store hints)
- Paridad `signingcert` ajustada a Java:
  - ahora excluye certificados de autenticación DNIe, pero no obliga a `nonRepudiation` en certificados no-DNIe.
- `batch` local firma con contexto de almacén:
  - se propagan `_defaultKeyStore`, `_defaultKeyStoreLib` y `_disableOpeningExternalStores` al firmador también en `executeBatchSingle`.
  - evita incoherencias entre `selectcert` de batch y lookup real en firma.
- Cobertura añadida:
  - `TestSigningCertFilterUsesNonRepudiationUsage` (actualizado a semántica Java real de signingcert)
  - `TestExecuteBatchSinglePropagatesStoreHintsToSigner`

### Nuevo avance (2026-02-17, selectcert qualified/ssl pairing)
- Mejora de robustez en emparejado de certificados para filtros `qualified`/`ssl`:
  - comparación de emisor más estricta (añadiendo `L` y `ST` cuando estén disponibles), manteniendo fallback compatible con el modelo actual.
  - objetivo: reducir emparejados falsos positivos sin romper casos válidos.
- Cobertura añadida:
  - `TestFindAssociatedSignatureCertRequiresSameIssuerDN`

### Nuevo avance (2026-02-17, batch trifásico PKCS1 con store context)
- Cierre de brecha en código real (no solo tests):
  - la firma PKCS#1 de lote trifásico (`PRE -> PK1`) ahora recibe y usa el mismo contexto de almacén (`defaultKeyStore/defaultKeyStoreLib/disableOpeningExternalStores`) que la selección/firma normal.
  - se añadió `SignPKCS1WithOptions(...)` en `pkg/signer` y el flujo batch remoto lo utiliza.
- Impacto:
  - mejora coherencia en escenarios con stores externos/PKCS#11 y reduce fallos por lookup de certificado fuera de contexto.
- Cobertura añadida:
  - `TestProcessProtocolRequestBatchRemoteJSONSuccess` ampliado para validar propagación de hints de store al PKCS1 trifásico.

### Nuevo avance (2026-02-17, properties case-insensitive en firma)
- Paridad de robustez en parseo de firma:
  - `buildProtocolSignOptions` ahora lee `properties` de forma case-insensitive (ej. `Properties`, `PROPERTIES`), igual que otros caminos protocolarios.
- Cobertura añadida:
  - `TestBuildProtocolSignOptionsReadsPropertiesCaseInsensitiveParam`

### Nuevo avance (2026-02-17, fix de store hints en firmador)
- Corrección funcional en `pkg/signer`:
  - `_disableOpeningExternalStores` se evaluaba como string y podía ignorarse cuando llegaba como booleano.
  - ahora se evalúa con parseo booleano real (`optionBool`), alineando comportamiento efectivo con lo que envía la GUI.
- Cobertura añadida:
  - `TestResolveCertstoreOptionsDisableExternalStoresBoolDisablesPKCS11`
  - `TestResolveCertstoreOptionsDisableExternalStoresDoesNotOverrideExplicitPKCS11`

### Nuevo avance (2026-02-17, fallback PKCS11 hints en firmador)
- Alineación adicional con `selectcert`:
  - en `pkg/signer`, si `defaultKeyStore=PKCS11` con `defaultKeyStoreLib` no devuelve certificados de token (`smartcard/dnie`), se reintenta automáticamente con descubrimiento PKCS#11 por defecto.
- Impacto:
  - reduce fallos de firma cuando la ruta de módulo aportada por integrador está desactualizada pero el token sí es detectable por la ruta estándar.
- Cobertura añadida:
  - `TestGetCertificatesForSignOptionsPKCS11HintsWithoutTokenFallbacksToDefaultDiscovery`

### Nuevo avance (2026-02-17, batch trifásico XML store hints)
- Consistencia completada en batch remoto XML:
  - validada propagación de `defaultKeyStore/defaultKeyStoreLib` también en la ruta XML de `PRE -> PK1`.
  - con esto queda cubierto en tests tanto JSON como XML para la prefirma cliente con contexto de almacén.
- Cobertura añadida:
  - `TestProcessProtocolRequestBatchRemoteXMLSuccess` ampliado con verificación de hints de store en PKCS1.

### Nuevo avance (2026-02-17, fallback PKCS11 directo en PKCS1)
- Implementación de código para cerrar hueco real de token no exportable en prefirma:
  - `SignPKCS1WithOptions` ahora, si falla exportación P12 y el contexto es PKCS#11 (`smartcard/dnie` o `defaultKeyStore=PKCS11`), intenta firma directa con PKCS#11.
  - se añadió backend Linux (`linux+cgo`) que:
    - localiza el certificado en token por DER,
    - resuelve la clave privada por `CKA_ID`,
    - firma con `CKM_RSA_PKCS`.
  - en plataformas no compatibles, mantiene comportamiento controlado con stub.
- Impacto:
  - reduce dependencia de `nickname`/`pk12util` en flujo trifásico (PRE->PK1), mejorando casos de token no exportable.
- Cobertura añadida:
  - `TestSignPKCS1WithOptionsFallsBackToPKCS11DirectSign`
  - `TestShouldTryPKCS11DirectSign`

### Nuevo avance (2026-02-17, PIN y extraparams en prefirma trifásica)
- Refuerzo en cadena de opciones hacia `PRE -> PK1`:
  - `protocol_sign_options` ahora propaga `pin` como `_pin`.
  - la prefirma trifásica remota integra también `extraparams` globales del batch (JSON y XML) en las opciones de firma.
  - parseo XML de batch actualizado para leer `extraparams` globales en `<signbatch>`.
- Impacto:
  - permite usar PIN explícito en escenarios de token durante fallback PKCS11 directo de PKCS1.
- Cobertura añadida:
  - `TestBuildProtocolSignOptionsPropagatesPINForSigner`
  - `TestParseBatchXMLRequestReadsGlobalExtraParams`
  - `TestProcessProtocolRequestBatchRemoteJSONSuccess` (ampliado: verifica `_pin`)
  - `TestProcessProtocolRequestBatchRemoteXMLSuccess` (ampliado: verifica `_pin`)

### Nuevo avance (2026-02-17, propagación efectiva de PIN a firmadores)
- `protocolSignOperation` ahora toma el PIN desde opciones (`_pin`/`pin`) cuando no se pasa explícito.
- `executeBatchSingle` pasa ese PIN al firmador en operaciones `sign/cosign/countersign`.
- Impacto:
  - mejora flujos con token que necesitan PIN en firma local/batch sin requerir cambios en integradores.
- Cobertura añadida:
  - `TestProtocolSignOperationTakesPinFromOptions`
  - `TestExecuteBatchSinglePropagatesStoreHintsToSigner` ampliado para verificar PIN.

### Nuevo avance (2026-02-17, robustez PKCS11 directo en PKCS1)
- Endurecida la firma directa PKCS11 en Linux:
  - tolera sesión ya autenticada (`CKR_USER_ALREADY_LOGGED_IN`).
  - mantiene firma por mecanismo `CKM_RSA_PKCS` (alineado con flujo `PRE -> PK1`).
- Impacto:
  - mejora robustez de sesión sin alterar semántica criptográfica esperada del `PK1`.

### Nuevo avance (2026-02-17, compat camelCase en JSON batch)
- `parseBatchJSONRequest` acepta variantes camelCase usadas por algunos integradores:
  - `stopOnError`, `subOperation`, `extraParams`, `singleSigns`, `dataReference`.
- Impacto:
  - mejora interoperabilidad de batch sin romper el formato ya soportado.
- Cobertura añadida:
  - `TestParseBatchJSONRequestSupportsCamelCaseCompat`

### Nuevo avance (2026-02-17, robustez extraParams por firma en batch remoto)
- Cierre de robustez en lote trifásico remoto:
  - se reutiliza el `batchRequest` ya parseado para construir opciones de firma (sin reprocesado del batch bruto).
  - mapeo de `extraParams` por firma ahora normaliza `id` de forma case-insensitive.
  - en JSON trifásico, si no llega `id` en `signinfo`, se usa `signid` como fallback para resolver opciones por firma.
- Impacto:
  - mejora compatibilidad con servicios de prefirma que varían el casing de identificadores o informan `signid` sin `id`.
- Cobertura añadida:
  - `TestBuildBatchRemoteSignOptionsNormalizesPerSignIDs`
  - `TestSignTriphaseDataAppliesPerSignOptionsBySignIDFallback`

### Nuevo avance (2026-02-17, fallback signid también en XML trifásico)
- En la firma `PRE -> PK1` de batch remoto XML, la resolución de `extraParams` por firma ahora también usa `signid` cuando `Id` no viene informado.
- Impacto:
  - mejora compatibilidad con respuestas de prefirma XML que identifican firma solo por `signid`.
- Cobertura añadida:
  - `TestSignTriphaseDataXMLAppliesPerSignOptionsBySignIDFallback`

### Nuevo avance (2026-02-17, sello visible PAdES ajustado)
- Texto del recuadro visible de firma PAdES mejorado:
  - contenido en 2 líneas: `CN=<...>` y `Firmado el dd/mm/yyyy HH:MM:SS por un certificado de la FNMT`.
  - tamaño de fuente máximo reducido al 50% respecto al comportamiento previo de la librería.
  - ajuste proporcional al tamaño del recuadro y truncado con elipsis para evitar desbordes.
  - alineación a la izquierda en el recuadro.
- Implementación técnica:
  - `github.com/digitorus/pdfsign` pasado a `replace` local (`third_party/pdfsign`) para persistir parche de apariencia multilinea.
- Cobertura añadida:
  - `TestBuildPadesVisibleSignatureTextIncludesCNAndFNMT`
  - `TestApplyPadesAppearanceOptionsSetsVisibleText`
