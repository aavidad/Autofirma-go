# Build macOS desde Linux con osxcross

Este proyecto usa Fyne con CGO, por lo que para macOS desde Linux necesitas `osxcross`.

## 1) Dependencias base (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y \
  clang cmake make patch git \
  libxml2-dev zlib1g-dev \
  xz-utils python3
```

## 2) Instalar osxcross

```bash
cd /tmp
git clone https://github.com/tpoechtrager/osxcross.git
cd osxcross
```

Coloca un SDK de macOS en `tarballs/` (por ejemplo `MacOSX*.sdk.tar.xz`).

```bash
UNATTENDED=1 ./build.sh
```

Al terminar, añade al `PATH`:

```bash
export PATH="/tmp/osxcross/target/bin:$PATH"
```

Si lo instalas en `/opt/osxcross`, usa:

```bash
export PATH="/opt/osxcross/target/bin:$PATH"
```

Comprueba toolchain:

```bash
which o64-clang
which oa64-clang
```

## 3) Compilar este proyecto para macOS

Desde la raíz del repo:

```bash
bash scripts/build_macos_osxcross.sh
```

Salida:
- `out/macos/autofirma-desktop-darwin-amd64`
- `out/macos/autofirma-desktop-darwin-arm64`

## 4) Notas

- El SDK de Apple es requisito para `osxcross`.
- Sin firma/notarización Apple, el binario puede requerir bypass de seguridad en macOS al abrirse.
