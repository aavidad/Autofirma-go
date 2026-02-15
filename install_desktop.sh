#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

mkdir -p ~/.local/share/applications
cat > ~/.local/share/applications/autofirma-dipgra.desktop <<EOL
[Desktop Entry]
Name=Autofirma Dipgra
Exec=/home/alberto/Trabajo/GrxGo/plugin_autofirma_native/native-host/dist/autofirma-desktop %u
Type=Application
Terminal=false
MimeType=x-scheme-handler/afirma;
Categories=Utility;
EOL

update-desktop-database ~/.local/share/applications
xdg-mime default autofirma-dipgra.desktop x-scheme-handler/afirma
echo "Desktop file installed and registered."
