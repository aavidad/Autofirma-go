# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

param(
  [switch]$StrictFormats,
  [switch]$SkipTrust
)

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot '..\\..')).Path
$Report = Join-Path $env:TEMP ("autofirma-full-validation-windows-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

function Add-Report([string]$Line) {
  Add-Content -Path $Report -Value $Line
}

function Run-Step([string]$Name, [scriptblock]$Action) {
  Write-Host "[full-check-win] $Name"
  Add-Report ("STEP: {0}" -f $Name)
  & $Action
  Add-Report 'RESULT: PASS'
}

try {
  Set-Location $RootDir
  Add-Report "date=$(Get-Date -Format o)"
  Add-Report "root=$RootDir"

  Run-Step '1/5 tests de código activo' { & powershell -ExecutionPolicy Bypass -File scripts/windows/test_active_go.ps1 }

  Run-Step '2/5 smoke host nativo' {
    if ($StrictFormats) {
      & powershell -ExecutionPolicy Bypass -File scripts/windows/smoke_native_host.ps1 -StrictFormats
    } else {
      & powershell -ExecutionPolicy Bypass -File scripts/windows/smoke_native_host.ps1
    }
  }

  if (-not $SkipTrust) {
    Run-Step '3/5 trust local windows' {
      & powershell -ExecutionPolicy Bypass -File scripts/windows/install_and_trust_windows.ps1 -SkipInstaller
    }
  } else {
    Write-Host '[full-check-win] 3/5 trust omitido por -SkipTrust'
    Add-Report 'STEP: 3/5 trust local windows'
    Add-Report 'RESULT: SKIP'
  }

  Run-Step '4/5 servidor web compat' {
    & powershell -ExecutionPolicy Bypass -File scripts/windows/run_web_compat_server.ps1 start
    & powershell -ExecutionPolicy Bypass -File scripts/windows/run_web_compat_server.ps1 status
  }

  Run-Step '5/5 parada controlada web compat' {
    & powershell -ExecutionPolicy Bypass -File scripts/windows/run_web_compat_server.ps1 stop
  }

  Add-Report 'RESULT_GLOBAL=PASS'
  Write-Host '[full-check-win] PASS'
  Write-Host "[full-check-win] reporte: $Report"
} catch {
  Add-Report ('RESULT_GLOBAL=FAIL: ' + $_.Exception.Message)
  Write-Host ('[full-check-win] FAIL: ' + $_.Exception.Message)
  Write-Host "[full-check-win] reporte: $Report"
  throw
}
