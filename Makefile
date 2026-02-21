# =============================================================================
# AutoFirma Dipgra — Makefile
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputación de Granada
# =============================================================================

VERSION      ?= $(shell cat VERSION 2>/dev/null | tr -d '[:space:]' || echo '0.0.1')
PREFIX       ?= /opt/autofirma-dipgra
QMAKE        ?= $(shell command -v qmake6 2>/dev/null || command -v qmake 2>/dev/null || echo qmake6)
GO           ?= go
NPROC        ?= $(shell nproc 2>/dev/null || echo 4)

DIST         := dist
GO_CORE_SRC  := ./cmd/gui
QT_DIR       := cmd/qt_real
GO_LDFLAGS   := -s -w -X main.Version=$(VERSION)

.PHONY: all build build-go build-qt install uninstall clean package help bump bump-minor bump-major version

# ─── Objetivo por defecto ─────────────────────────────────────────────────────
all: build

help:  ## Muestra esta ayuda
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ─── Compilación ──────────────────────────────────────────────────────────────
build: build-go build-qt copy-qml  ## Compila todo (Go + Qt)
	@echo "VERSION=$(VERSION)" > $(DIST)/VERSION
	@echo ""
	@echo "✅ Build completo en $(DIST)/"
	@ls -lh $(DIST)/

build-go: $(DIST)  ## Compila el backend Go (autofirma-desktop)
	@echo "▶  Compilando backend Go..."
	$(GO) build -trimpath -ldflags="$(GO_LDFLAGS)" -o $(DIST)/autofirma-desktop $(GO_CORE_SRC)
	@chmod +x $(DIST)/autofirma-desktop
	@echo "   → $(DIST)/autofirma-desktop"

build-qt: $(DIST)  ## Compila el frontend Qt (autofirma-qt)
	@echo "▶  Compilando frontend Qt..."
	@cd $(QT_DIR) && \
		$(QMAKE) qt_real.pro -spec linux-g++ CONFIG+=release && \
		make -j$(NPROC)
	@cp $(QT_DIR)/qt_real $(DIST)/autofirma-qt
	@chmod +x $(DIST)/autofirma-qt
	@echo "   → $(DIST)/autofirma-qt"

copy-qml: $(DIST)  ## Copia los archivos QML al directorio dist
	@echo "▶  Copiando QML..."
	@mkdir -p $(DIST)/qml
	@cp -a $(QT_DIR)/qml/. $(DIST)/qml/
	@echo "   → $(DIST)/qml/"

build-host:  ## Compila el native messaging host (si existe)
	@if [ -d cmd/host ]; then \
		echo "▶  Compilando native messaging host..."; \
		$(GO) build -trimpath -ldflags="-s -w" -o $(DIST)/autofirma-host ./cmd/host; \
		chmod +x $(DIST)/autofirma-host; \
		echo "   → $(DIST)/autofirma-host"; \
	else \
		echo "⚠  cmd/host no encontrado, skipping."; \
	fi

# ─── Instalación ──────────────────────────────────────────────────────────────
install: build  ## Compila e instala en el sistema (requiere sudo)
	@echo "▶  Instalando en $(PREFIX)..."
	@sudo VERSION=$(VERSION) PREFIX=$(PREFIX) \
		packaging/linux/build_and_install.sh --no-build --prefix $(PREFIX)

install-only:  ## Instala sin recompilar (usa dist/ existente)
	@sudo VERSION=$(VERSION) PREFIX=$(PREFIX) \
		packaging/linux/build_and_install.sh --no-build --prefix $(PREFIX)

uninstall:  ## Desinstala la aplicación del sistema (requiere sudo)
	@sudo PREFIX=$(PREFIX) packaging/linux/build_and_install.sh --uninstall --no-build --prefix $(PREFIX)

# ─── Paquete distribuible ─────────────────────────────────────────────────────
package: build  ## Crea un tarball instalador autónomo
	@echo "▶  Empaquetando..."
	@mkdir -p release/linux
	@# Crear directorio payload con todo lo necesario
	@rm -rf release/linux/payload
	@mkdir -p release/linux/payload/AutofirmaDipgra
	@cp dist/autofirma-desktop        release/linux/payload/AutofirmaDipgra/
	@cp dist/autofirma-qt             release/linux/payload/AutofirmaDipgra/
	@cp -a dist/qml                   release/linux/payload/AutofirmaDipgra/
	@[ -f dist/autofirma-host ] && cp dist/autofirma-host release/linux/payload/AutofirmaDipgra/ || true
	@echo "$(VERSION)" > release/linux/payload/AutofirmaDipgra/VERSION
	@# Copiar instalador y certificados
	@cp packaging/linux/build_and_install.sh  release/linux/payload/install.sh
	@chmod +x release/linux/payload/install.sh
	@[ -d packaging/linux/certs ] && cp -a packaging/linux/certs release/linux/payload/ || true
	@# Crear tarball
	@cd release/linux/payload && \
		tar czf ../AutofirmaDipgra-$(VERSION)-linux-x64.tar.gz .
	@echo ""
	@echo "✅ Paquete: release/linux/AutofirmaDipgra-$(VERSION)-linux-x64.tar.gz"
	@echo ""
	@echo "Para instalar desde el paquete:"
	@echo "  tar xzf AutofirmaDipgra-$(VERSION)-linux-x64.tar.gz"
	@echo "  sudo ./install.sh --prefix $(PREFIX)"

# ─── Limpieza ─────────────────────────────────────────────────────────────────
clean:  ## Limpia artefactos de compilación
	@echo "▶  Limpiando..."
	@rm -rf $(DIST)
	@cd $(QT_DIR) && make clean 2>/dev/null || true
	@rm -f $(QT_DIR)/qt_real $(QT_DIR)/autofirma-desktop
	@echo "   Listo."

clean-all: clean  ## Limpia todo incluyendo releases
	@rm -rf release/linux/payload release/linux/*.tar.gz

# ─── Directorio dist ──────────────────────────────────────────────────────────
# ─── Versión ─────────────────────────────────────────────────────────────────
version:  ## Muestra la versión actual
	@cat VERSION

bump:  ## Sube versión PATCH (0.0.1 → 0.0.2) y actualiza CHANGELOG
	@./bump_version.sh --patch --message "$(MSG)"

bump-minor:  ## Sube versión MINOR (0.0.x → 0.1.0)
	@./bump_version.sh --minor --message "$(MSG)"

bump-major:  ## Sube versión MAJOR (0.x.x → 1.0.0)
	@./bump_version.sh --major --message "$(MSG)"

# ─── Directorio dist ──────────────────────────────────────────────────────────
$(DIST):
	@mkdir -p $(DIST)
