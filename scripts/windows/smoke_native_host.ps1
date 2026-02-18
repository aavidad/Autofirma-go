# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

param(
  [switch]$StrictFormats
)

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot '..\\..')).Path
$Bin = Join-Path $RootDir 'autofirma-host-smoke.exe'
$PdfTest = Join-Path $RootDir 'testdata\\original.pdf'

if (-not $env:GOFLAGS -or $env:GOFLAGS -notmatch '(^|\s)-mod=') {
  if ([string]::IsNullOrWhiteSpace($env:GOFLAGS)) { $env:GOFLAGS = '-mod=readonly' } else { $env:GOFLAGS = "$($env:GOFLAGS) -mod=readonly" }
}
if (-not $env:GOCACHE -or [string]::IsNullOrWhiteSpace($env:GOCACHE)) {
  $env:GOCACHE = Join-Path $env:TEMP 'go-build'
}

Set-Location $RootDir
Write-Host '[smoke-win] compilando host nativo...'
& go build -o $Bin ./cmd/autofirma-host

function Read-Exact([System.IO.Stream]$Stream, [int]$Count) {
  $buf = New-Object byte[] $Count
  $readTotal = 0
  while ($readTotal -lt $Count) {
    $n = $Stream.Read($buf, $readTotal, $Count - $readTotal)
    if ($n -le 0) {
      if ($readTotal -eq 0) { return $null }
      throw "Trama incompleta al leer $Count bytes"
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
    throw "Host nativo falló (código $($proc.ExitCode)): $errText"
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

function Assert-True([bool]$Value, [string]$Message) {
  if (-not $Value) { throw $Message }
}

$ping = Invoke-Native '{"requestId":"1","action":"ping"}'
Write-Host ("[smoke-win] ping => success={0}" -f $ping.success)
Assert-True ([bool]$ping.success) 'Ping no exitoso.'

$certResp = Invoke-Native '{"requestId":"2","action":"getCertificates"}'
$certCount = if ($certResp.certificates) { $certResp.certificates.Count } else { 0 }
Write-Host ("[smoke-win] getCertificates => success={0} count={1}" -f $certResp.success, $certCount)
Assert-True ([bool]$certResp.success) 'getCertificates falló.'
if ($certCount -le 0) {
  Write-Host '[smoke-win] WARN: no hay certificados disponibles; prueba parcial OK'
  exit 0
}
$certId = [string]$certResp.certificates[0].id

$signReq = @{ requestId='3'; action='sign'; certificateId=$certId; data='SG9sYQ=='; format='cades' } | ConvertTo-Json -Compress
$signResp = Invoke-Native $signReq
Write-Host ("[smoke-win] sign(cades) => success={0} len={1}" -f $signResp.success, $signResp.signatureLen)
Assert-True ([bool]$signResp.success) 'Firma CAdES falló.'
Assert-True (-not [string]::IsNullOrWhiteSpace([string]$signResp.signature)) 'Firma CAdES vacía.'

$verifyReq = @{ requestId='4'; action='verify'; format='cades'; originalData='SG9sYQ=='; signatureData=[string]$signResp.signature } | ConvertTo-Json -Compress
$verifyResp = Invoke-Native $verifyReq
Write-Host ("[smoke-win] verify(cades) => success={0} valid={1}" -f $verifyResp.success, $verifyResp.result.valid)
Assert-True ([bool]$verifyResp.success) 'Verificación CAdES falló.'
Assert-True ([bool]$verifyResp.result.valid) 'Verificación CAdES inválida.'

if (Test-Path $PdfTest) {
  $pdfB64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($PdfTest))
  $signPReq = @{ requestId='5'; action='sign'; certificateId=$certId; data=$pdfB64; format='pades' } | ConvertTo-Json -Compress
  $signP = Invoke-Native $signPReq
  Write-Host ("[smoke-win] sign(pades) => success={0}" -f $signP.success)

  if ($StrictFormats -and -not [bool]$signP.success) { throw 'Firma PAdES falló en modo estricto.' }
  if ([bool]$signP.success -and -not [string]::IsNullOrWhiteSpace([string]$signP.signature)) {
    $verifyPReq = @{ requestId='6'; action='verify'; format='pades'; originalData=[string]$signP.signature } | ConvertTo-Json -Compress
    $verifyP = Invoke-Native $verifyPReq
    Write-Host ("[smoke-win] verify(pades) => success={0} valid={1}" -f $verifyP.success, $verifyP.result.valid)
    if ($StrictFormats) {
      Assert-True ([bool]$verifyP.success) 'Verificación PAdES falló en modo estricto.'
      Assert-True ([bool]$verifyP.result.valid) 'Verificación PAdES inválida en modo estricto.'
    }
  }
} else {
  Write-Host "[smoke-win] pades => SKIP (no existe $PdfTest)"
}

$xmlData = '<root><valor>hola</valor></root>'
$xmlB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($xmlData))
$signXReq = @{ requestId='7'; action='sign'; certificateId=$certId; data=$xmlB64; format='xades' } | ConvertTo-Json -Compress
$signX = Invoke-Native $signXReq
Write-Host ("[smoke-win] sign(xades) => success={0}" -f $signX.success)
if ($StrictFormats -and -not [bool]$signX.success) { throw 'Firma XAdES falló en modo estricto.' }
if ([bool]$signX.success -and -not [string]::IsNullOrWhiteSpace([string]$signX.signature)) {
  $verifyXReq = @{ requestId='8'; action='verify'; format='xades'; originalData=$xmlB64; signatureData=[string]$signX.signature } | ConvertTo-Json -Compress
  $verifyX = Invoke-Native $verifyXReq
  Write-Host ("[smoke-win] verify(xades) => success={0} valid={1}" -f $verifyX.success, $verifyX.result.valid)
  if ($StrictFormats) {
    Assert-True ([bool]$verifyX.success) 'Verificación XAdES falló en modo estricto.'
    Assert-True ([bool]$verifyX.result.valid) 'Verificación XAdES inválida en modo estricto.'
  }
}

Write-Host '[smoke-win] PASS'
