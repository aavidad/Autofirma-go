//go:build !windows

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import "fmt"

func nativeOpenFileDialogWindows(title, initialPath, exts string, multi bool) ([]string, bool, error) {
	return nil, false, fmt.Errorf("dialogo nativo de Windows no disponible en este sistema")
}

func nativeSaveFileDialogWindows(title, defaultPath, exts string) (string, bool, error) {
	return "", false, fmt.Errorf("dialogo nativo de Windows no disponible en este sistema")
}
