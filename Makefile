# =============================================================================
# AutoFirma Dipgra — Makefile (Reorganized)
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputación de Granada
# =============================================================================

VERSION      ?= $(shell cat VERSION 2>/dev/null | tr -d '[:space:]' || echo '0.0.1')
PREFIX       ?= /opt/autofirma-dipgra
QMAKE        ?= $(shell command -v qmake6 2>/dev/null || command -v qmake 2>/dev/null || echo qmake6)
GO           ?= go
NPROC        ?= $(shell nproc 2>/dev/null || echo 4)

DIST         := dist
CORE_DIR     := cmd/autofirma
QML_DIR      := cmd/gui-qml
WIDGETS_DIR  := cmd/gui-widgets
BRIDGE_DIR   := cmd/browser-bridge

GO_LDFLAGS   := -s -w -X main.Version=$(VERSION)

.PHONY: all build build-core build-qml build-widgets build-bridge install uninstall clean package help bump bump-minor bump-major version

# ─── Objetivo por defecto ─────────────────────────────────────────────────────
all: build

help:  ## Muestra esta ayuda
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2}'

# ─── Compilación ──────────────────────────────────────────────────────────────
build: build-core build-qml build-widgets build-bridge copy-assets  ## Compila todo (Core + GUIs + Bridge)
	@echo "$(VERSION)" > $(DIST)/VERSION
	@echo ""
	@echo "✅ Build completo en $(DIST)/"
	@ls -F $(DIST)/

build-core: $(DIST)  ## Compila el motor principal (incluye GUIs Fyne/Gio)
	@echo "▶  Compilando Core (Go)..."
	$(GO) build -trimpath -ldflags="$(GO_LDFLAGS)" -o $(DIST)/autofirma ./$(CORE_DIR)
	@chmod +x $(DIST)/autofirma
	@echo "   → $(DIST)/autofirma"

build-qml: $(DIST)  ## Compila la interfaz moderna QML
	@echo "▶  Compilando GUI Premium (QML)..."
	@cd $(QML_DIR) && \
		$(QMAKE) *.pro -spec linux-g++ CONFIG+=release && \
		make -j$(NPROC)
	@# Buscamos el ejecutable generado
	@find $(QML_DIR) -maxdepth 1 -type f -executable -not -name "*.pro" -not -name "*.sh" -not -name "*.o" -exec cp {} $(DIST)/autofirma-gui-qml \;
	@chmod +x $(DIST)/autofirma-gui-qml
	@echo "   → $(DIST)/autofirma-gui-qml"

build-widgets: $(DIST)  ## Compila la interfaz clásica Qt Widgets
	@echo "▶  Compilando GUI Clásica (Widgets)..."
	@cd $(WIDGETS_DIR) && \
		$(QMAKE) *.pro -spec linux-g++ CONFIG+=release && \
		make -j$(NPROC)
	@# Buscamos el ejecutable generado
	@find $(WIDGETS_DIR) -maxdepth 1 -type f -executable -not -name "*.pro" -not -name "*.sh" -not -name "*.o" -exec cp {} $(DIST)/autofirma-gui-widgets \;
	@chmod +x $(DIST)/autofirma-gui-widgets
	@echo "   → $(DIST)/autofirma-gui-widgets"

build-bridge: $(DIST)  ## Compila el Native Messaging Host
	@echo "▶  Compilando Browser Bridge..."
	$(GO) build -trimpath -ldflags="-s -w" -o $(DIST)/autofirma-browser-bridge ./$(BRIDGE_DIR)
	@chmod +x $(DIST)/autofirma-browser-bridge
	@echo "   → $(DIST)/autofirma-browser-bridge"

copy-assets: $(DIST)  ## Organiza QML y Assets en dist/
	@echo "▶  Organizando recursos..."
	@mkdir -p $(DIST)/qml $(DIST)/assets
	@cp -a $(QML_DIR)/qml/. $(DIST)/qml/
	@[ -d assets ] && cp -a assets/. $(DIST)/assets/ || true
	@echo "   → $(DIST)/qml/"
	@echo "   → $(DIST)/assets/"

# ─── Instalación ──────────────────────────────────────────────────────────────
install: build  ## Compila e instala en el sistema (requiere sudo)
	@echo "▶  Instalando en $(PREFIX)..."
	@sudo VERSION=$(VERSION) PREFIX=$(PREFIX) \
		scripts/build_and_install.sh --no-build --prefix $(PREFIX)

uninstall:  ## Desinstala la aplicación del sistema (requiere sudo)
	@sudo PREFIX=$(PREFIX) scripts/build_and_install.sh --uninstall --no-build --prefix $(PREFIX)

# ─── Paquete distribuible ─────────────────────────────────────────────────────
package: build  ## Crea un tarball instalador autónomo
	@echo "▶  Empaquetando..."
	@mkdir -p release/linux/payload/AutofirmaDipgra
	@cp -a $(DIST)/* release/linux/payload/AutofirmaDipgra/
	@# Copiar instalador y certificados
	@cp scripts/build_and_install.sh  release/linux/payload/install.sh
	@chmod +x release/linux/payload/install.sh
	@[ -d packaging/linux/certs ] && cp -a packaging/linux/certs release/linux/payload/ || true
	@# Crear tarball
	@cd release/linux/payload && \
		tar czf ../AutofirmaDipgra-$(VERSION)-linux-x64.tar.gz .
	@echo "✅ Paquete: release/linux/AutofirmaDipgra-$(VERSION)-linux-x64.tar.gz"

# ─── Limpieza ─────────────────────────────────────────────────────────────────
clean:  ## Limpia artefactos de compilación
	@echo "▶  Limpiando..."
	@rm -rf $(DIST)
	@cd $(QML_DIR) && make clean 2>/dev/null || true
	@cd $(WIDGETS_DIR) && make clean 2>/dev/null || true
	@rm -f $(QML_DIR)/qt_real $(WIDGETS_DIR)/autofirma-gui-widgets
	@echo "   Listo."

# ─── Versión ─────────────────────────────────────────────────────────────────
version:
	@cat VERSION

bump:
	@./bump_version.sh --patch --message "$(MSG)"

bump-minor:
	@./bump_version.sh --minor --message "$(MSG)"

bump-major:
	@./bump_version.sh --major --message "$(MSG)"

$(DIST):
	@mkdir -p $(DIST)
