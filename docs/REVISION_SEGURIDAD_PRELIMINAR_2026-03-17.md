# Revision preliminar de seguridad y cumplimiento

Fecha: 2026-03-17
Repositorio: `work/native-host-src`
Estado: borrador tecnico para discusion con otros agentes

## Alcance de esta revision

Revision local del proyecto Go orientada a:
- manejo de claves y certificados;
- persistencia temporal de material sensible;
- autenticacion de canales locales;
- validacion criptografica;
- higiene operativa de logs y artefactos.

Este documento recoge solo hallazgos verificados en el arbol local. No incluye aun contraste formal con normativa o fuentes oficiales.

Documento complementario revisado:
- `/home/alberto/Trabajo/AutoFirma_Dipgra/REVISION_AUTOFIRMA_CONTAGRX_20260317.md`

Ese documento esta mas orientado a comparar `native-host-src` con revisiones historicas de ContaGrx y a proponer bloques de cambio en `signer`/`certstore`. Este informe se centra en riesgos locales de seguridad y cumplimiento observables en el estado actual del codigo.

## Hallazgos

### 1. Critico: hay rutas de firma que siguen materializando clave privada en disco

Evidencia:
- `pkg/signer/pkcs1.go:57-77`
- `pkg/signer/cades_openssl.go:18-23`
- `pkg/signer/cades_openssl.go:44-51`
- `pkg/signer/signer.go:272`
- `pkg/signer/signer.go:479`
- `pkg/signer/signer.go:487`

Detalle:
- La ruta PKCS#1 crea ficheros temporales en `os.TempDir()` y extrae la clave privada a `autofirma-pk1-key-*.pem`.
- La ruta CAdES basada en OpenSSL crea `autofirma-key-*.pem` y `autofirma-cert-*.pem` en disco.
- El propio codigo reconoce el riesgo y ofrece `AUTOFIRMA_STRICT_NO_DISK_KEY_MATERIAL=1`, pero no es el comportamiento por defecto.

Impacto:
- exposición de material de clave privada en disco;
- riesgo de recuperacion forense, backup accidental o lectura por otro proceso del mismo usuario;
- tension clara con hardening serio de firma local.

### 2. Critico: la autenticacion por certificado REST no valida cadena de confianza; con allowlist vacia acepta cualquier certificado no expirado

Evidencia:
- `cmd/autofirma/rest_server.go:329`
- `cmd/autofirma/rest_server.go:546-560`
- `cmd/autofirma/rest_server.go:1373-1397`
- `cmd/autofirma/rest_server.go:1399-1411`

Detalle:
- `parseAuthCertificate()` solo parsea el X.509 y calcula huella.
- `handleAuthVerify()` comprueba allowlist solo si existe; si no existe, solo exige vigencia temporal.
- La prueba criptografica del reto verifica que el cliente posee la privada del certificado aportado, pero no que el certificado sea de confianza, cualificado, emitido por una CA admitida o con EKU/politica adecuada.

Impacto:
- cualquier tercero con un certificado autofirmado vigente y su clave privada podria autenticarse por `challenge/verify` si el servicio se expone y no hay allowlist configurada.

### 3. Alto: la UI clasica levanta el REST en `0.0.0.0`, amplificando el problema anterior

Evidencia:
- `cmd/autofirma/ui_gio.go:6342-6357`
- `cmd/autofirma/rest_server.go:242-245`

Detalle:
- El modo CLI por defecto usa `127.0.0.1:63118`.
- La UI Gio construye la direccion como `0.0.0.0:<puerto>` y llama a `runRESTServer(...)`.

Impacto:
- el servicio deja de ser solo local y pasa a estar accesible desde red si el host tiene conectividad;
- combinado con el hallazgo anterior, el vector deja de ser local y pasa a ser remoto.

### 4. Alto: los sockets Unix IPC/REST quedan con permisos `0666`

Evidencia:
- `cmd/autofirma/ipc_handler.go:34-40`
- `cmd/autofirma/rest_server.go:382-387`

Detalle:
- tanto el socket IPC como el socket Unix del REST se crean y luego se fuerzan a `0666`.
- eso permite acceso de cualquier usuario local con visibilidad del path.

Impacto:
- ampliacion innecesaria de superficie de ataque local;
- posibilidad de invocacion por otros usuarios del sistema en equipos compartidos o multiusuario.

### 5. Alto: la compatibilidad Java exporta un PKCS#12 con contraseña fija y conocida (`654321`)

Evidencia:
- `cmd/autofirma/tls_certs.go:22-28`
- `cmd/autofirma/tls_certs.go:207-218`
- `PLAN_MIGRACION_AUTOFIRMA_GO.md` documenta esta compatibilidad como decision de producto.

Detalle:
- el fichero `autofirma.pfx` se genera con alias `SocketAutoFirma` y password fija `654321`.
- aunque sea por compatibilidad con AutoFirma Java, sigue siendo una credencial predecible para un artefacto que contiene clave privada.

Impacto:
- cualquier copia del `.pfx` queda efectivamente desprotegida;
- mala señal de cumplimiento si no se documenta como excepcion muy acotada y controlada.

### 6. Alto: la importacion de P12/PFX usa ficheros temporales y expone contraseñas en linea de comandos del sistema

Evidencia:
- `cmd/autofirma/ipc_handler.go:107-118`
- `cmd/autofirma/rest_server.go:674-688`
- `pkg/certstore/import.go:62`
- `pkg/certstore/import.go:82-84`
- `pkg/certstore/import.go:99-105`

Detalle:
- IPC y REST decodifican el P12 en un fichero temporal local para importarlo.
- Linux usa `pk12util -W <password>`.
- Windows construye un `powershell -Command` con la contraseña en claro.
- macOS llama a `security import ... -P <password>`.

Impacto:
- residuos temporales de P12 en disco;
- contraseñas potencialmente visibles en listados de procesos, trazas o herramientas de diagnostico.

### 7. Medio: la verificacion CAdES con OpenSSL usa `-noverify`

Evidencia:
- `pkg/signer/cades_openssl.go:97-121`

Detalle:
- se valida la estructura y la coherencia criptografica del CMS, pero no la cadena de confianza del firmante.

Impacto:
- riesgo de que capas superiores interpreten la respuesta como validacion completa de firma cuando en realidad es validacion de integridad/estructura.

### 8. Medio: los logs persistentes se crean con permisos `0644`

Evidencia:
- `pkg/applog/applog.go:35`
- `pkg/applog/applog.go:45`
- `pkg/applog/applog.go:49-53`

Detalle:
- el directorio de logs se crea con `0755`;
- los ficheros se abren con `0644`;
- existe sanitizacion parcial, pero el propio proceso registra argumentos, errores criptograficos y metadatos de sesion.

Impacto:
- exposicion innecesaria de trazas operativas a otros usuarios locales del equipo.

### 9. Medio: existen artefactos de `SSLKEYLOGFILE` en el arbol de trabajo

Evidencia local:
- `.ssl-key.log`
- `dist/.ssl-key.log`
- `.gitignore:22`

Detalle:
- el repo ya ignora `.ssl-key.log`, pero en este workspace existen al menos dos artefactos.
- su sola presencia indica que en algun momento se habilito exportacion de secretos de sesion TLS para diagnostico.

Impacto:
- si contienen material real de sesiones, permiten descifrar trafico capturado correspondiente;
- problema de higiene operacional incluso aunque no esten versionados.

## Observaciones positivas

- Existe ya una via de endurecimiento explicita para prohibir material de clave en disco: `AUTOFIRMA_STRICT_NO_DISK_KEY_MATERIAL=1`.
- El proyecto tiene utilidades de saneado de logs (`pkg/applog/sanitize.go`) y no todo el logging es ingenuo.
- El modo CLI del REST parte de `127.0.0.1`, lo que reduce riesgo frente al arranque desde UI.

## Relacion con la revision ContaGrx

Coincidencias claras con el documento complementario:
- persisten rutas de exportacion temporal a PKCS#12 y material sensible en disco;
- `pk12util` sigue recibiendo secretos por linea de comandos;
- el fallback OpenSSL para CAdES merece iteracion propia;
- la parte XAdES actual parece mas XMLDSig funcional que XAdES-BES completo.

Hallazgos que este informe añade y que conviene discutir aparte:
- autenticacion REST por certificado sin validacion de cadena de confianza;
- exposicion del REST en `0.0.0.0` desde la UI Gio;
- sockets Unix con permisos `0666`;
- exportacion `autofirma.pfx` con password fija `654321`;
- verificacion CAdES con `-noverify`;
- permisos laxos en logs y presencia de artefactos `.ssl-key.log`.

## Orden propuesto de remediacion

1. Cerrar la autenticacion REST: exigir allowlist o trust-chain real, y evitar exposicion en `0.0.0.0` por defecto.
2. Endurecer IPC/REST local: sockets `0600` o `0660`, y rutas seguras por usuario.
3. Eliminar por defecto cualquier ruta que escriba claves privadas en disco, o hacer obligatorio el modo estricto.
4. Replantear la exportacion PFX de compatibilidad Java para que la excepcion quede muy acotada o controlada.
5. Separar semanticamente "verificacion criptografica basica" de "verificacion de confianza".
6. Pasar logs y artefactos sensibles a permisos privados y limpiar residuos de `SSLKEYLOGFILE`.

## Preguntas abiertas para la discusion

- La compatibilidad con AutoFirma Java obliga realmente a mantener el `.pfx` con password fija o se puede encapsular mejor esa transicion?
- El login por certificado REST estaba pensado solo para confianza explicita por huella o se asumio erróneamente que cualquier X.509 vigente era suficiente?
- El arranque del REST en `0.0.0.0` desde Gio es una decision consciente de producto o un atajo de desarrollo que se quedo?
- La verificacion CAdES actual se presenta a integradores como validacion de confianza o solo como verificacion tecnica de firma?
