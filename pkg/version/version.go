// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package version

const (
	CurrentVersion   = "0.0.48"
	DefaultUpdateURL = "https://autofirma.dipgra.es/version.json"
)

var (
	// Se pueden sobrescribir en compilacion con -ldflags:
	// -X autofirma-host/pkg/version.BuildCommit=<hash>
	// -X autofirma-host/pkg/version.BuildDate=<YYYY-MM-DDTHH:MM:SSZ>
	BuildCommit = "local"
	BuildDate   = "desconocida"
)
