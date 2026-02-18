# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

param(
  [switch]$StrictFormats,
  [switch]$SkipTrust
)

$argsList = @('-ExecutionPolicy','Bypass','-File','scripts/windows/run_full_validation_windows.ps1')
if ($StrictFormats) { $argsList += '-StrictFormats' }
if ($SkipTrust) { $argsList += '-SkipTrust' }

powershell @argsList
