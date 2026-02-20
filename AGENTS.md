# AutoFirma Java -> Go Session Rules

Licencia: GPLv3.
Autor: Alberto Avidad Fernandez.
Organizacion: Oficina de Software Libre de la Diputacion de Granada.

## Contexto del proyecto
- Proyecto: migracion de AutoFirma desde Java a Go.
- Objetivo principal: que la app Go haga como minimo todo lo que hace la app Java (`clienteafirma-master`) y, cuando sea posible, lo mejore sin romper compatibilidad.
- Ruta de trabajo principal: `/home/alberto/Trabajo/AutoFirma_Dipgra/autofirma_migracion/work/native-host-src`.

## Objetivo funcional obligatorio
- Prioridad maxima: compatibilidad funcional 100% del nucleo de firma respecto a Java.
- Regla de mejora: no copiar por copiar; si una implementacion Go es compatible y objetivamente mejor (robustez, seguridad, mantenibilidad, rendimiento), se mantiene la mejora.
- Regla de no regresion: cualquier cambio debe preservar compatibilidad con flujos y parametros de integracion existentes.

## Archivos obligatorios a revisar al iniciar sesion
Leer siempre antes de tocar codigo:
- `PLAN_MIGRACION_AUTOFIRMA_GO.md` (fuente principal de estado y pendientes reales).
- `AVANCES_PARIDAD_JAVA_GO.md` (resumen ejecutivo de avances/paridad).
- `SESSION_TRACKER.md` (continuidad de contexto de sesiones).

## Politica de trabajo sobre codigo
- Enfocarse primero en el nucleo Go (protocolo, signer, certstore, batch, websocket, service).
- No hacer cambios cosmeticos innecesarios.
- Cambiar solo cuando aporte una de estas 3 cosas:
  1. cerrar una brecha real de compatibilidad Java->Go,
  2. mejorar calidad sin romper compatibilidad,
  3. corregir bug/regresion demostrable.
- Antes de cerrar tarea, ejecutar pruebas disponibles del proyecto (como minimo `go test` en cmd/gui y pkg) si el entorno lo permite.

## Validacion y criterios de cierre
- No dar por cerrada una funcionalidad solo por compilar: exigir evidencia (tests, logs o validacion E2E).
- Para flujos de sede/websocket, distinguir claramente:
  - fallo de producto,
  - bloqueo de entorno (sandbox/red/certificados/desktop handler).
- Mantener trazabilidad de pendientes reales hacia el 100% funcional.

## Documentacion obligatoria al terminar cambios
Tras cada bloque relevante de trabajo:
- actualizar `PLAN_MIGRACION_AUTOFIRMA_GO.md` con:
  - avances implementados,
  - estado de paridad,
  - pendientes reales.
- actualizar `AVANCES_PARIDAD_JAVA_GO.md` con resumen ejecutivo coherente.
- si procede, registrar decision/resultado en `SESSION_TRACKER.md`.

## Git y commits (obligatorio)
- Crear commit en cada progreso real de desarrollo (no acumular cambios grandes sin commit).
- Antes de cada commit:
  - validar que compila/testea en el alcance tocado (si el entorno lo permite),
  - actualizar archivos de seguimiento (`PLAN_MIGRACION_AUTOFIRMA_GO.md`, `AVANCES_PARIDAD_JAVA_GO.md` y `SESSION_TRACKER.md` cuando aplique).
- Mensajes de commit:
  - claros, concretos y orientados a paridad Java->Go,
  - describiendo que funcionalidad se cierra o que brecha se reduce.

## Prioridades tecnicas permanentes
1. Compatibilidad funcional Java->Go del nucleo de firma.
2. Seguridad del canal e integraciones locales (host/desktop/websocket/native messaging).
3. Robustez operativa (errores SAF, reintentos, validaciones de entrada, logs saneados).
4. Packaging/release Linux y Windows sin perder paridad funcional.

## Regla de colaboracion
- Guiar al usuario con pasos concretos cuando haya validaciones manuales (firma real, seleccion de certificado, prueba en sede).
- Automatizar por consola todo lo automatizable.
- Si un bloqueo depende de GUI/usuario, preparar el entorno y dejar instrucciones minimas y precisas.
