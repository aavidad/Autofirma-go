# AutoFirma Dipgra - Guía Exhaustiva de Uso y Funcionamiento

Licencia: GPLv3.
Autor: Alberto Avidad Fernandez.
Organizacion: Oficina de Software Libre de la Diputacion de Granada.

## 1. Objetivo de la aplicación
AutoFirma Dipgra es un cliente de firma electrónica compatible con flujos `afirma://` (estilo AutoFirma Java), con interfaz gráfica y backend en Go.

Permite:
- Firmar documentos localmente (CAdES, PAdES, XAdES).
- Verificar firmas.
- Operar con flujos de sede electrónica (`rtservlet`/`stservlet`, WebSocket WSS, canal service legacy).
- Ejecutar lotes (batch) locales y remotos.
- Diagnosticar incidencias de red, certificados y canal de firma.

## 2. Componentes y arquitectura
### 2.1 GUI (`cmd/gui`)
Interfaz principal para usuario final.

Responsabilidades:
- Selección de archivo y certificado.
- Lanzamiento de firma/verificación.
- Ejecución de protocolo `afirma://`.
- Gestión de modo simple/experto.
- Diagnóstico local y generación de reportes técnicos.

### 2.2 Motor de firma (`pkg/signer`)
Implementa operaciones criptográficas:
- CAdES.
- PAdES (incluido sello visible configurable).
- XAdES.
- Cofirma/contrafirma según flujo soportado.
- Verificación de firmas.

### 2.3 Almacén de certificados (`pkg/certstore`)
Carga certificados de:
- NSS/sistema.
- Windows Store (en Windows).
- PKCS#11 (tokens, DNIe), con hints opcionales (`defaultKeyStoreLib`).

### 2.4 Protocolo y compatibilidad (`cmd/gui/protocol*.go`, `websocket*.go`)
Resuelve URIs `afirma://` y sus variantes:
- `sign`, `cosign`, `countersign`, `save`, `selectcert`, `batch`, `websocket`, `service`.

## 3. Modos de uso
### 3.1 Modo simple
Enfocado a uso directo:
- Cargar archivo.
- Elegir certificado.
- Firmar o verificar.

### 3.2 Modo experto
Expone herramientas avanzadas:
- `selectcert` manual.
- Carga/guardado avanzados.
- Lote local por JSON/XML.
- Diagnóstico completo y autoprueba guiada.
- Opciones de compatibilidad estricta.
- Gestión de certificados del sistema y exportación segura PKCS#12.

## 4. Flujos de firma y “vueltas”
En esta guía, “vueltas” significa intercambio de ida y vuelta entre cliente y sede/servicio.

### 4.1 Firma local (sin sede)
1. Usuario selecciona archivo.
2. GUI prepara datos de entrada (base64 + opciones).
3. GUI solicita firma al motor.
4. Motor firma con certificado seleccionado.
5. GUI presenta resultado y permite guardar.

No hay “vueltas” de red obligatorias, salvo validaciones opcionales.

### 4.2 Firma protocolaria con `afirma://sign` y descarga previa (`rtservlet`)
1. Navegador/sede lanza URI `afirma://...`.
2. La app parsea parámetros.
3. Si existe `rtservlet`, descarga petición de firma.
4. Se interpreta contenido (incluido XML AutoFirma si aplica).
5. Usuario firma en GUI.
6. Se devuelve resultado:
- por WebSocket (si flujo WSS), o
- por subida legacy (`stservlet`) si aplica.

Aquí hay varias “vueltas”:
- Vuelta 1: sede -> app (URI).
- Vuelta 2: app -> sede (`rtservlet`, descarga).
- Vuelta 3: app -> sede (`stservlet` o respuesta WSS).

### 4.3 Flujo WebSocket seguro local (WSS)
1. Sede pide abrir `afirma://websocket?...` con puertos.
2. App abre servidor WSS local en loopback.
3. La web conecta por WSS.
4. La web envía operaciones (`sign`, `save`, etc.).
5. La app responde por el mismo socket.

Ventajas:
- Menor dependencia de subida legacy.
- Trazabilidad clara en logs WSS.

### 4.4 Flujo service legacy
1. Sede/envío legacy fragmenta comandos en canal tipo `service`.
2. App reensambla payload.
3. Ejecuta operación.
4. Devuelve resultado codificado con formato legacy.

Se mantiene por compatibilidad con sedes antiguas.

### 4.5 Batch local
1. Usuario carga JSON/XML de lote.
2. Se parsean operaciones.
3. Para cada firma se resuelven opciones y certificado.
4. Se firma una a una.
5. Se genera resultado agregado.

### 4.6 Batch remoto trifásico (`PRE -> PK1 -> POST`)
1. App solicita prefirma (`PRE`) al servidor.
2. App realiza firma local PKCS#1 (`PK1`) con el certificado.
3. App devuelve datos de firma al servidor para completar (`POST`).

“Vueltas” típicas:
- Vuelta A: app -> servidor (prefirma).
- Vuelta B: app (firma local PK1).
- Vuelta C: app -> servidor (ensamblado/finalización).

## 5. Formatos de firma
### 5.1 CAdES
Para datos binarios o contenido general.

### 5.2 PAdES
Para PDF.
- Puede incluir sello visible.
- Puede advertir si el PDF no es totalmente válido.
- Existe opción para permitir continuar bajo confirmación explícita.

### 5.3 XAdES
Para XML u otros escenarios compatibles con XAdES.

## 6. Compatibilidad estricta
Modo para aproximar comportamiento conservador al cliente Java en casos límite.

Cuándo activarlo:
- Errores protocolarios no reproducibles en local.
- Sedes antiguas con validaciones muy cerradas.
- Incompatibilidades de parámetros no estándar.

Efecto esperado:
- Menos tolerancia a interpretaciones amplias.
- Mayor alineación con semántica legacy.

## 7. Diagnóstico y resolución de incidencias
### 7.1 Diagnóstico rápido
Revisa:
- Estado de certificados.
- Red básica.
- Conectividad con endpoints críticos.
- Indicios de proxy/firewall.
- Posible interferencia TLS de antivirus/proxy.

### 7.2 Chequeo completo
Incluye:
- Diagnóstico rápido.
- Autoprueba guiada de firma.
- Reporte técnico consolidado.

### 7.3 Historial y panel de incidencias
La GUI registra:
- Operación.
- Formato.
- Resultado.
- Detalle de error.
- Posible solución accionable.

## 8. Errores típicos y qué significan
### 8.1 No se encuentra certificado
Causas habituales:
- Certificado no cargado en almacén activo.
- Token no conectado.
- Filtro de `selectcert` demasiado restrictivo.

Acciones:
- Revisar almacén/certificado seleccionado.
- Reintentar con modo experto para inspección detallada.
- Abrir el gestor de certificados del sistema desde el botón de la app.

### 8.2 Error de red con @firma/sede
Causas habituales:
- DNS no resuelve.
- Firewall/proxy bloquea salida.
- Endpoint remoto no disponible.

Acciones:
- Ejecutar diagnóstico rápido.
- Revisar proxy corporativo y reglas de salida.

### 8.3 Error TLS o posible inspección HTTPS
Causas habituales:
- Proxy/antivirus intercepta TLS.
- Certificado presentado no coincide con el host esperado.

Acciones:
- Crear excepción para `autofirma.dipgra.es` y endpoints de sede.
- Revisar política de inspección HTTPS.

### 8.4 Rechazo del servidor al subir firma
Causas habituales:
- Endpoint incorrecto.
- Firma demasiado grande.
- Respuesta no compatible.

Acciones:
- Revisar logs protocolarios.
- Probar compatibilidad estricta.
- Verificar límites y disponibilidad del servidor.

### 8.5 Exportación de certificado PKCS#12
Criterios de la app:
- La exportación se realiza en formato PKCS#12 (`.p12/.pfx`).
- Se usa una clave temporal con requisitos de seguridad alta.
- La clave temporal se puede generar y copiar al portapapeles desde la UI.

## 9. Logs y evidencias
Rutas habituales Linux:
- `~/.local/state/autofirma-dipgra/logs/`
- `/tmp/autofirma-web-compat.log`

Buenas prácticas:
- Compartir extractos recientes saneados (sin datos sensibles).
- Anotar hora exacta de la prueba.
- Guardar reporte técnico generado desde la GUI.

## 10. Recomendaciones operativas
- Mantener app y entorno de certificados actualizados.
- Probar primero con documento pequeño de control.
- Si falla una sede concreta, validar también en otra para aislar si es problema local o remoto.
- Ante error recurrente, adjuntar reporte completo + log saneado.

## 11. Límites y alcance actual
- Se mantiene compatibilidad alta con flujos Java habituales, pero la validación final depende también de cada sede y su backend.
- Pueden existir diferencias en casuística extrema de proveedores criptográficos concretos.
- Se recomienda validación E2E real por sede objetivo antes de cerrar despliegue definitivo.

## 12. Atajos de validación recomendados
- Prueba rápida de host/firma: scripts smoke.
- Prueba de canal WSS: scripts de web compat.
- Prueba real de sede: `run_sede_e2e.sh` + revisión de logs.

## 13. Panel de pruebas en la GUI (modo experto)
La aplicación incluye un panel de pruebas integrado para ejecutar scripts desde la interfaz:
- Selección individual o múltiple de pruebas.
- Botón de ejecución por prueba.
- Ejecución de pruebas seleccionadas o de todas.
- Resultado y salida visibles en el panel de mensajes con scroll.

Referencia de scripts y uso detallado:
- `docs/SCRIPTS_PRUEBAS.md`
