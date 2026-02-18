# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $RootDir

if (-not $env:GOCACHE -or [string]::IsNullOrWhiteSpace($env:GOCACHE)) {
  $env:GOCACHE = Join-Path $env:TEMP 'go-build'
}
if (-not $env:GOFLAGS -or $env:GOFLAGS -notmatch '(^|\s)-mod=') {
  if ([string]::IsNullOrWhiteSpace($env:GOFLAGS)) {
    $env:GOFLAGS = '-mod=readonly'
  } else {
    $env:GOFLAGS = "$($env:GOFLAGS) -mod=readonly"
  }
}

Write-Host '[test-active-win] recopilando paquetes Go activos (cmd/, pkg/)...'
$pkgs = @(& go list ./cmd/... ./pkg/...)
if ($pkgs.Count -eq 0) {
  throw 'No se encontraron paquetes activos para pruebas.'
}

Write-Host ("[test-active-win] ejecutando go test sobre {0} paquetes..." -f $pkgs.Count)
& go test @pkgs
Write-Host '[test-active-win] OK'
