# Compatibilidad Navegadores (Firefox, Chrome, Edge)

Licencia: GPLv3.
Autor: Alberto Avidad Fernandez.
Organizacion: Oficina de Software Libre de la Diputacion de Granada.

## Objetivo
Permitir invocar la app desde enlaces `afirma://...` en navegadores de escritorio.

## Requisitos
- App instalada con instalador oficial del proyecto.
- Registro de protocolo `afirma` activo en el sistema.
- Certificado del usuario disponible en el store del sistema.

## Windows
El instalador registra:
- `HKCR\\afirma`
- `HKLM\\Software\\Classes\\afirma`
- `HKCU\\Software\\Classes\\afirma`

Con esto, Chrome, Edge y Firefox pueden abrir `afirma://` mediante el handler del sistema.

## Linux
El instalador registra:
- Desktop entry `autofirma-dipgra.desktop` con `MimeType=x-scheme-handler/afirma`
- Asociación con `xdg-mime` y `xdg-settings`
- `mimeapps.list` para el usuario que ejecutó `sudo`.

## Comportamiento por navegador
- Chrome / Edge: normalmente muestran un diálogo de confirmación la primera vez para abrir aplicación externa.
- Firefox: puede pedir confirmación para abrir enlace externo.

Esto es comportamiento de seguridad del navegador y no debe desactivarse de forma global en instalación estándar.

## Verificación rápida
1. Abrir en navegador: `afirma://test`
2. Debe lanzarse la aplicación.
3. Probar una firma real en sede con `afirma://sign?...`.

## Nota sobre certificados en Windows
La app lista certificados de `Cert:\\CurrentUser\\My` con clave privada.
Si la clave no es exportable, puede fallar la firma al exportar PFX temporal.
