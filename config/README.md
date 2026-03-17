# Configuración Estática de Dominios

Estos archivos definen qué dominios web tienen permiso para interactuar con AutoFirma Dipgra.

| Archivo | Propósito |
| :--- | :--- |
| `dominios_firma_permitidos.txt` | Lista de dominios que pueden solicitar operaciones de firma. Previene que sitios maliciosos intenten usar la app sin permiso. |
| `dominios_firma_autoconfiados.txt` | Dominios de alta confianza que no requieren confirmación adicional para ciertas operaciones (uso interno de la Diputación). |

## Formato
*   Un dominio por línea (ej: `dipgra.es`).
*   Las líneas que empiezan por `#` son comentarios.
*   Se pueden usar comodines básicos si la lógica del Core lo soporta.
