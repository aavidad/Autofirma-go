# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

param(
  [ValidateSet('start','stop','restart','status')]
  [string]$Action = 'start'
)

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot '..\\..')).Path
$Bin = Join-Path $RootDir 'autofirma-web-compat.exe'
$Ports = if ($env:AUTOFIRMA_WS_PORTS) { $env:AUTOFIRMA_WS_PORTS } else { '63117,63118,63119' }
$LogFile = if ($env:AUTOFIRMA_WS_LOG) { $env:AUTOFIRMA_WS_LOG } else { (Join-Path $env:TEMP 'autofirma-web-compat.log') }
$PidFile = Join-Path $RootDir 'out\\web_compat_server_windows.pid'

if (-not $env:GOFLAGS -or $env:GOFLAGS -notmatch '(^|\s)-mod=') {
  if ([string]::IsNullOrWhiteSpace($env:GOFLAGS)) { $env:GOFLAGS = '-mod=readonly' } else { $env:GOFLAGS = "$($env:GOFLAGS) -mod=readonly" }
}
if (-not $env:GOCACHE -or [string]::IsNullOrWhiteSpace($env:GOCACHE)) {
  $env:GOCACHE = Join-Path $env:TEMP 'go-build'
}

function Build-Bin {
  Write-Host '[web-compat-win] compilando servidor GUI...'
  Set-Location $RootDir
  & go build -o $Bin ./cmd/gui
}

function Get-RunningPid {
  if (-not (Test-Path $PidFile)) { return $null }
  $pidValue = (Get-Content $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
  if ([string]::IsNullOrWhiteSpace($pidValue)) { return $null }
  try {
    $proc = Get-Process -Id ([int]$pidValue) -ErrorAction Stop
    return $proc.Id
  } catch {
    Remove-Item $PidFile -ErrorAction SilentlyContinue
    return $null
  }
}

function Start-Server {
  $running = Get-RunningPid
  if ($running) {
    Write-Host "[web-compat-win] ya está en ejecución pid=$running"
    return
  }

  Build-Bin
  New-Item -ItemType Directory -Force -Path (Split-Path $PidFile -Parent) | Out-Null
  New-Item -ItemType Directory -Force -Path (Split-Path $LogFile -Parent) | Out-Null

  Write-Host "[web-compat-win] iniciando en puertos: $Ports"
  Write-Host "[web-compat-win] log: $LogFile"

  $env:AUTOFIRMA_WS_PORTS = $Ports
  $proc = Start-Process -FilePath $Bin -ArgumentList '--server' -RedirectStandardOutput $LogFile -RedirectStandardError $LogFile -PassThru
  Set-Content -Path $PidFile -Value $proc.Id
  Start-Sleep -Milliseconds 250

  try {
    $check = Get-Process -Id $proc.Id -ErrorAction Stop
    Write-Host "[web-compat-win] pid=$($check.Id)"
  } catch {
    Remove-Item $PidFile -ErrorAction SilentlyContinue
    throw "El servidor salió durante el arranque. Revisa: $LogFile"
  }
}

function Stop-Server {
  $running = Get-RunningPid
  if (-not $running) {
    Write-Host '[web-compat-win] no está en ejecución'
    return
  }
  Stop-Process -Id $running -Force -ErrorAction SilentlyContinue
  Remove-Item $PidFile -ErrorAction SilentlyContinue
  Write-Host "[web-compat-win] detenido pid=$running"
}

function Status-Server {
  $running = Get-RunningPid
  if ($running) {
    Write-Host "[web-compat-win] en ejecución pid=$running"
    exit 0
  }
  Write-Host '[web-compat-win] detenido'
  exit 1
}

switch ($Action) {
  'start' { Start-Server }
  'stop' { Stop-Server }
  'restart' { Stop-Server; Start-Server }
  'status' { Status-Server }
}
