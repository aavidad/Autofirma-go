# Manual de Usuario

Licencia: GPLv3.
Autor: Alberto Avidad Fernandez.
Organizacion: Oficina de Software Libre de la Diputacion de Granada.

## 1. Que es AutoFirma Dipgra
AutoFirma Dipgra es una aplicacion de firma electronica compatible con el ecosistema de AutoFirma (`afirma://`) sin depender de Java.

Permite:
- Identificacion con certificado (`selectcert`).
- Firma de documentos (CAdES, PAdES, XAdES).
- Firma por lotes (`batch`).
- Flujos web por `Native Messaging`, `WSS` y subida legacy.

## 2. Requisitos
- Certificado digital instalado y vigente (persona fisica o representacion).
- Navegador actualizado.
- Sistema operativo: Windows, Linux o macOS.

## 3. Instalacion
### Linux
1. Ejecutar instalador `.run`.
2. Reiniciar navegador.

### Windows
1. Ejecutar instalador `.exe`.
2. Reiniciar navegador.

### macOS
1. Ejecutar instalador del paquete correspondiente.
2. Conceder permisos necesarios y reiniciar navegador.

## 4. Uso normal (modo simple)
1. Inicie el tramite en la sede.
2. Acepte el lanzamiento de la aplicacion cuando el navegador lo solicite.
3. Seleccione certificado.
4. Confirme la operacion.
5. Espere respuesta de la sede.

Nota: en flujos de identificacion solo se mostrara seleccion de certificado. En flujos de firma documental se mostraran controles de documento/firma segun el protocolo recibido.

## 5. Modo experto
El modo experto expone utilidades avanzadas:
- Diagnostico de red y TLS.
- Panel de pruebas con ejecucion de scripts.
- Gestion de dominios de confianza (lista blanca).
- Herramientas de certificados y exportacion.
- Historial y trazas tecnicas.

## 6. Seguridad integrada
### Lista blanca de dominios
Cuando una web no conocida solicita operar con `afirma://`, la app puede pedir confirmacion y registrar el dominio.

Incluye:
- Alta/baja de dominios de confianza.
- Avisos de riesgo si el dominio no esta en lista blanca.

### Diagnostico de red y TLS
La app puede comprobar:
- Resolucion DNS.
- Conectividad TCP/TLS con endpoints.
- Posible interferencia de proxy/firewall/antivirus.
- Estado de certificados remotos y de confianza local.

### Confianza local
Comandos disponibles:
- `autofirma-desktop -generate-certs`
- `autofirma-desktop -install-trust`
- `autofirma-desktop -trust-status`

## 7. Gestion de certificados
- La lista muestra certificados aptos para firma.
- Si se detecta certificado de representacion, se etiqueta como `[representación]`.
- Si falta un certificado esperado:
  - Verifique vigencia.
  - Verifique almacen activo del navegador/sistema.
  - Revise token/DNIe y controladores.

## 8. Errores y soluciones recomendadas
### Error de conectividad con sede
- Ejecute diagnostico rapido.
- Revise DNS, proxy y firewall.
- Reintente con navegador reiniciado.

### Error TLS con servicios de prefirma/postfirma
- Revise mensaje de emisor/certificado reportado por la app.
- Instale certificados intermedios necesarios (FNMT u organismo emisor) en el almacen del sistema.
- Reintente tras actualizar confianza.

### Error en lote (`SAF_*`)
- Revise panel de mensajes y diagnostico.
- Verifique endpoints de pre/post firma.
- Si la sede funciona con AutoFirma Java pero falla aqui, active diagnostico y guarde reporte para soporte.

## 9. Ayuda dentro de la app
- Boton de ayuda general.
- Ayuda de scripts de pruebas desde modo experto.
- Panel de mensajes con scroll para seguimiento de resultados.

## 10. Reportes para soporte
Cuando abra incidencia:
1. Incluya hora exacta de la prueba.
2. Adjunte log reciente de `~/.local/state/autofirma-dipgra/logs/` (Linux) o ruta equivalente en su SO.
3. Adjunte reporte de diagnostico exportado desde la app.
