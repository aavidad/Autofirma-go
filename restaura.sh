# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

# 1. Crear el lanzador original
echo '[Desktop Entry]
Encoding=UTF-8
Version=1.0
Type=Application
Terminal=false
Exec=java -jar /usr/lib/AutoFirma/AutoFirma.jar %u
Name=AutoFirma
Icon=autofirma
Categories=Application;Utilities;
MimeType=x-scheme-handler/afirma;' > ~/.local/share/applications/es-gob-afirma.desktop

# 2. Asignarlo por defecto
xdg-mime default es-gob-afirma.desktop x-scheme-handler/afirma

# 3. Activar logs (asegurarnos de que existe la config)
mkdir -p ~/.afirma/AutoFirma
echo "secure.domains=*" >> ~/.afirma/AutoFirma/AutoFirmaConfig.properties
# Normalmente AutoFirma ya loguea todo en ~/.afirma/AutoFirma/autofirma.log
