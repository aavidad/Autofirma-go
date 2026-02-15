#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

cd /home/alberto/Trabajo/GrxGo/plugin_autofirma_native/native-host
echo "Launching Go AutoFirma with args: $@" >> /tmp/autofirma-go.log
./autofirma-host "$@" >> /tmp/autofirma-go.log 2>&1
