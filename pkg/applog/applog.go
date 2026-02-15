// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package applog

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	mu          sync.Mutex
	currentPath string
)

// Init configures process logging to a persistent file + stderr.
func Init(appName string) (string, error) {
	mu.Lock()
	defer mu.Unlock()

	logDir, err := defaultLogDir()
	if err != nil || strings.TrimSpace(logDir) == "" {
		logDir = fallbackLogDir()
	}
	if err := os.MkdirAll(logDir, 0755); err != nil {
		alt := fallbackLogDir()
		if alt != logDir {
			_ = os.MkdirAll(alt, 0755)
			logDir = alt
		}
	}

	fileName := fmt.Sprintf("%s-%s.log", sanitizeName(appName), time.Now().Format("2006-01-02"))
	path := filepath.Join(logDir, fileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		// Last-resort fallback to temp directory.
		tmpPath := filepath.Join(os.TempDir(), "AutofirmaDipgra", "logs")
		if mkErr := os.MkdirAll(tmpPath, 0755); mkErr != nil {
			return "", err
		}
		path = filepath.Join(tmpPath, fileName)
		f, err = os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return "", err
		}
	}

	log.SetOutput(io.MultiWriter(os.Stderr, f))
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.LUTC | log.Lshortfile)
	currentPath = path

	cleanupOldLogs(logDir, 14)
	return path, nil
}

func Path() string {
	mu.Lock()
	defer mu.Unlock()
	return currentPath
}

func fallbackLogDir() string {
	return filepath.Join(os.TempDir(), "AutofirmaDipgra", "logs")
}

func defaultLogDir() (string, error) {
	switch runtime.GOOS {
	case "windows":
		base := strings.TrimSpace(os.Getenv("LOCALAPPDATA"))
		if base == "" {
			userProfile := strings.TrimSpace(os.Getenv("USERPROFILE"))
			if userProfile == "" {
				return "", fmt.Errorf("LOCALAPPDATA/USERPROFILE no disponibles")
			}
			base = filepath.Join(userProfile, "AppData", "Local")
		}
		return filepath.Join(base, "AutofirmaDipgra", "logs"), nil
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "Library", "Logs", "AutofirmaDipgra"), nil
	default:
		base := strings.TrimSpace(os.Getenv("XDG_STATE_HOME"))
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			base = filepath.Join(home, ".local", "state")
		}
		return filepath.Join(base, "autofirma-dipgra", "logs"), nil
	}
}

func sanitizeName(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return "autofirma"
	}
	var b strings.Builder
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func cleanupOldLogs(dir string, keepDays int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type fi struct {
		name string
		mod  time.Time
	}
	var files []fi
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".log") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, fi{name: e.Name(), mod: info.ModTime()})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod.Before(files[j].mod) })
	cutoff := time.Now().AddDate(0, 0, -keepDays)
	for _, f := range files {
		if f.mod.After(cutoff) {
			continue
		}
		_ = os.Remove(filepath.Join(dir, f.name))
	}
}
