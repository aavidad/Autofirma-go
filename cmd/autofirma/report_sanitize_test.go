// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"strings"
	"testing"
)

func TestSanitizeReportLogLineSanitizesAfirmaURI(t *testing.T) {
	in := "[WebSocket] Received: afirma://save?dat=ABC123&idsession=foo"
	out := sanitizeReportLogLine(in)
	if out == in {
		t.Fatalf("expected sanitized output, got unchanged")
	}
	if strings.Contains(out, "dat=ABC123") {
		t.Fatalf("expected dat to be redacted, got %q", out)
	}
	if !strings.Contains(out, "dat=%5BREDACTED%5D") {
		t.Fatalf("expected redacted dat marker, got %q", out)
	}
}

func TestSanitizeReportLogLineTruncatesLongLines(t *testing.T) {
	long := strings.Repeat("a", 400)
	out := sanitizeReportLogLine(long)
	if len(out) > 270 {
		t.Fatalf("expected truncated output, got len=%d", len(out))
	}
	if !strings.Contains(out, "...(trunc)") {
		t.Fatalf("expected truncation suffix, got %q", out)
	}
}
