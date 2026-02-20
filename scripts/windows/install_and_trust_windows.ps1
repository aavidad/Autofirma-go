# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

param(
  [string]$InstallerPath = '',
  [switch]$SkipInstaller
)

function Resolve-AppBinary {
  $candidates = @(
    (Join-Path $env:ProgramFiles 'AutofirmaDipgra\\autofirma-desktop.exe'),
    (Join-Path $env:LOCALAPPDATA 'AutofirmaDipgra\\autofirma-desktop.exe')
  )
  foreach ($c in $candidates) {
    if (Test-Path $c) { return $c }
  }
  $cmd = Get-Command autofirma-dipgra.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  throw 'No se encontró autofirma-desktop/autofirma-dipgra en el sistema.'
}

if (-not $SkipInstaller) {
  if ([string]::IsNullOrWhiteSpace($InstallerPath)) {
    throw 'Debes indicar -InstallerPath C:\\ruta\\instalador.exe o usar -SkipInstaller.'
  }
  if (-not (Test-Path $InstallerPath)) {
    throw "Instalador no encontrado: $InstallerPath"
  }
  Write-Host "[install-trust-win] ejecutando instalador: $InstallerPath"
  Start-Process -FilePath $InstallerPath -Verb RunAs -Wait
}

$appBin = Resolve-AppBinary
Write-Host "[install-trust-win] binario detectado: $appBin"

Write-Host '[install-trust-win] generando certificados locales...'
& $appBin '--generate-certs'

Write-Host '[install-trust-win] exportando certificados compatibles de AutoFirma Java...'
$appDir = Split-Path -Parent $appBin
& $appBin '--exportar-certs-java' $appDir

Write-Host '[install-trust-win] aplicando trust...'
& $appBin '--install-trust'

Write-Host '[install-trust-win] estado de trust...'
& $appBin '--trust-status'

if ($appDir) {
  $fnmtCert = Join-Path $appDir 'certs\fnmt-accomp.crt'
  if (Test-Path $fnmtCert) {
    Write-Host '[install-trust-win] instalando CA FNMT ACCOMP en Root/CA...'
    certutil -addstore -f Root $fnmtCert | Out-Null
    certutil -addstore -f CA $fnmtCert | Out-Null
  }
}

Write-Host '[install-trust-win] OK'
