// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package updater

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Manifest struct {
	Version string `json:"version"`
	URL     string `json:"url,omitempty"`
	Notes   string `json:"notes,omitempty"`
}

type Result struct {
	CurrentVersion string
	LatestVersion  string
	UpdateURL      string
	HasUpdate      bool
}

func CheckForUpdates(currentVersion, manifestURL string) (*Result, error) {
	manifestURL = strings.TrimSpace(manifestURL)
	if manifestURL == "" {
		return nil, fmt.Errorf("URL de actualizacion vacia")
	}

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(manifestURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("estado HTTP no valido: %d", resp.StatusCode)
	}

	var m Manifest
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, fmt.Errorf("json de version invalido: %v", err)
	}
	if strings.TrimSpace(m.Version) == "" {
		return nil, fmt.Errorf("json sin campo 'version'")
	}

	return &Result{
		CurrentVersion: strings.TrimSpace(currentVersion),
		LatestVersion:  strings.TrimSpace(m.Version),
		UpdateURL:      strings.TrimSpace(m.URL),
		HasUpdate:      compareVersions(strings.TrimSpace(m.Version), strings.TrimSpace(currentVersion)) > 0,
	}, nil
}

func compareVersions(a, b string) int {
	parse := func(v string) []int {
		v = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(v), "v"))
		parts := strings.Split(v, ".")
		out := make([]int, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				out = append(out, 0)
				continue
			}
			n, err := strconv.Atoi(p)
			if err != nil {
				n = 0
			}
			out = append(out, n)
		}
		return out
	}

	aa := parse(a)
	bb := parse(b)
	max := len(aa)
	if len(bb) > max {
		max = len(bb)
	}
	for i := 0; i < max; i++ {
		av := 0
		bv := 0
		if i < len(aa) {
			av = aa[i]
		}
		if i < len(bb) {
			bv = bb[i]
		}
		if av > bv {
			return 1
		}
		if av < bv {
			return -1
		}
	}
	return 0
}
