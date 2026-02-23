#!/bin/bash
export SUDO_USER="alberto"
export USER="alberto"
export HOME="/home/alberto"
export PATH=$PATH

source scripts/build_and_install.sh --no-build --prefix /tmp/autofirma_install_test
