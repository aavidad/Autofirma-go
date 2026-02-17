//go:build !windows

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import "fmt"

func nativeCopyToClipboardWindows(_ string) error {
	return fmt.Errorf("portapapeles nativo de Windows no disponible en este sistema")
}
