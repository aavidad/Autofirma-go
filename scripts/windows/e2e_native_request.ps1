# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

param(
  [ValidateSet('ping','getCertificates','sign-cades')]
  [string]$Action = 'ping'
)

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot '..\\..')).Path
$Bin = Join-Path $RootDir 'autofirma-host-e2e.exe'

if (-not $env:GOFLAGS -or $env:GOFLAGS -notmatch '(^|\s)-mod=') {
  if ([string]::IsNullOrWhiteSpace($env:GOFLAGS)) { $env:GOFLAGS = '-mod=readonly' } else { $env:GOFLAGS = "$($env:GOFLAGS) -mod=readonly" }
}
if (-not $env:GOCACHE -or [string]::IsNullOrWhiteSpace($env:GOCACHE)) {
  $env:GOCACHE = Join-Path $env:TEMP 'go-build'
}

Set-Location $RootDir
& go build -o $Bin ./cmd/autofirma-host

function Read-Exact([System.IO.Stream]$Stream, [int]$Count) {
  $buf = New-Object byte[] $Count
  $readTotal = 0
  while ($readTotal -lt $Count) {
    $n = $Stream.Read($buf, $readTotal, $Count - $readTotal)
    if ($n -le 0) {
      if ($readTotal -eq 0) { return $null }
      throw "Trama incompleta al leer $Count bytes (leídos: $readTotal)"
    }
    $readTotal += $n
  }
  return $buf
}

function Invoke-Native([string]$PayloadJson) {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $Bin
  $psi.UseShellExecute = $false
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true

  $proc = New-Object System.Diagnostics.Process
  $proc.StartInfo = $psi
  [void]$proc.Start()

  $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($PayloadJson)
  $lenBytes = [System.BitConverter]::GetBytes([uint32]$payloadBytes.Length)
  $stdin = $proc.StandardInput.BaseStream
  $stdin.Write($lenBytes, 0, 4)
  $stdin.Write($payloadBytes, 0, $payloadBytes.Length)
  $stdin.Flush()
  $stdin.Close()

  $frames = @()
  $stdout = $proc.StandardOutput.BaseStream
  while ($true) {
    $frameLenBytes = Read-Exact $stdout 4
    if ($null -eq $frameLenBytes) { break }
    $frameLen = [System.BitConverter]::ToUInt32($frameLenBytes, 0)
    $frameBytes = Read-Exact $stdout ([int]$frameLen)
    $frames += [System.Text.Encoding]::UTF8.GetString($frameBytes)
  }

  $proc.WaitForExit()
  if ($proc.ExitCode -ne 0) {
    $errText = $proc.StandardError.ReadToEnd()
    throw "El host devolvió código $($proc.ExitCode): $errText"
  }

  if ($frames.Count -eq 0) {
    throw 'No se recibió respuesta del host.'
  }
  if ($frames.Count -eq 1) {
    return ($frames[0] | ConvertFrom-Json)
  }

  $objs = @($frames | ConvertFrom-Json | Sort-Object chunk)
  $first = $objs[0]
  $sig = ($objs | ForEach-Object { if ($_.signature) { $_.signature } else { '' } }) -join ''
  Add-Member -InputObject $first -NotePropertyName signature -NotePropertyValue $sig -Force
  Add-Member -InputObject $first -NotePropertyName totalChunks -NotePropertyValue $objs.Count -Force
  Add-Member -InputObject $first -NotePropertyName chunk -NotePropertyValue 0 -Force
  return $first
}

switch ($Action) {
  'ping' {
    $r = Invoke-Native '{"requestId":"100","action":"ping"}'
    $r | ConvertTo-Json -Compress
  }
  'getCertificates' {
    $r = Invoke-Native '{"requestId":"101","action":"getCertificates"}'
    $r | ConvertTo-Json -Compress
  }
  'sign-cades' {
    $certResp = Invoke-Native '{"requestId":"102","action":"getCertificates"}'
    if (-not $certResp.certificates -or $certResp.certificates.Count -eq 0) {
      throw 'No hay certificados disponibles para firmar.'
    }
    $certId = [string]$certResp.certificates[0].id
    $req = @{ requestId='103'; action='sign'; certificateId=$certId; data='SG9sYQ=='; format='cades' } | ConvertTo-Json -Compress
    $r = Invoke-Native $req
    $r | ConvertTo-Json -Compress
  }
}
