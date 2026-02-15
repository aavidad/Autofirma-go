# Logging y trazas

La app ahora escribe logs persistentes por proceso:

- GUI: `autofirma-desktop-YYYY-MM-DD.log`
- Host nativo: `autofirma-host-YYYY-MM-DD.log`

## Rutas de logs

- Windows: `%LOCALAPPDATA%\AutofirmaDipgra\logs\`
- Linux: `${XDG_STATE_HOME:-~/.local/state}/autofirma-dipgra/logs/`
- macOS: `~/Library/Logs/AutofirmaDipgra/`

## Qué revisar para errores de exportación PAdES en Windows

Busca estas líneas:

- `[Signer] Intentando exportar certificado a PFX...`
- `[Signer] Win cert diagnostics ... data=...`
- `[Exec] Export-PfxCertificate error ...`

Las trazas de `Win cert diagnostics` incluyen:

- `HasPrivateKey`
- `PrivateKeyType`
- `LegacyExportable`
- `HardwareDevice`
- `ProviderName`
- `RsaPrivateKeyType`
- `CngProvider`
- `CngExportPolicy`

Con esas líneas se puede determinar si la clave privada existe pero no es exportable por política/proveedor.
