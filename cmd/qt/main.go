// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func main() {
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("[QT] no se pudo resolver ejecutable: %v", err)
	}
	exeDir := filepath.Dir(exePath)

	realQtCandidates := []string{}
	if env := strings.TrimSpace(os.Getenv("AUTOFIRMA_QT_BIN_REAL")); env != "" {
		realQtCandidates = append(realQtCandidates, env)
	}
	realQtCandidates = append(realQtCandidates, localExecutableCandidates(exeDir, "autofirma-desktop-qt-real")...)
	realQtCandidates = append(realQtCandidates, "autofirma-desktop-qt-real")

	if realQt := resolveExecutable(realQtCandidates...); realQt != "" {
		log.Printf("[QT] usando frontend Qt nativo: %s", realQt)
		if err := runChild(realQt, os.Args[1:], buildQtRuntimeEnv(exeDir, filepath.Dir(realQt))); err != nil {
			log.Fatalf("[QT] frontend Qt nativo falló: %v", err)
		}
		return
	}

	if strings.TrimSpace(os.Getenv("AUTOFIRMA_QT_FALLBACK_FYNE")) != "1" {
		log.Fatalf("[QT] no hay frontend Qt nativo instalado. Configure AUTOFIRMA_QT_BIN_REAL o instale autofirma-desktop-qt-real")
	}

	guiPath := resolveExecutable(localExecutableCandidates(exeDir, "autofirma-desktop")...)
	if guiPath == "" {
		log.Fatalf("[QT] no se encontró autofirma-desktop junto a qt-bin")
	}
	log.Printf("[QT] fallback temporal activo: delegando en frontend Fyne")
	args := sanitizeDesktopArgs(os.Args[1:])
	args = append([]string{"-fyne"}, args...)
	if err := runChild(guiPath, args, nil); err != nil {
		log.Fatalf("[QT] delegación a Fyne fallida: %v", err)
	}
}

func resolveExecutable(candidates ...string) string {
	for _, c := range candidates {
		if strings.TrimSpace(c) == "" {
			continue
		}
		if strings.ContainsRune(c, filepath.Separator) {
			if st, err := os.Stat(c); err == nil && !st.IsDir() {
				return c
			}
			continue
		}
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	return ""
}

func localExecutableCandidates(baseDir, baseName string) []string {
	candidates := []string{filepath.Join(baseDir, baseName)}
	if runtime.GOOS == "windows" {
		candidates = append(candidates, filepath.Join(baseDir, baseName+".exe"))
	}
	return candidates
}

func sanitizeDesktopArgs(in []string) []string {
	out := make([]string, 0, len(in))
	skipNext := false
	for _, a := range in {
		if skipNext {
			skipNext = false
			continue
		}
		la := strings.ToLower(strings.TrimSpace(a))
		if la == "-qt" || la == "--qt" || la == "-fyne" || la == "--fyne" || la == "-gio" || la == "--gio" {
			continue
		}
		if la == "-frontend" || la == "--frontend" {
			skipNext = true
			continue
		}
		if strings.HasPrefix(la, "-frontend=") || strings.HasPrefix(la, "--frontend=") {
			continue
		}
		out = append(out, a)
	}
	return out
}

func runChild(bin string, args []string, env []string) error {
	cmd := exec.Command(bin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %v: %w", bin, args, err)
	}
	return nil
}

func buildQtRuntimeEnv(exeDir, realQtDir string) []string {
	runtimeDir := strings.TrimSpace(os.Getenv("AUTOFIRMA_QT_RUNTIME_DIR"))
	if runtimeDir == "" {
		candidates := []string{
			filepath.Join(exeDir, "qt-runtime"),
			filepath.Join(realQtDir, "qt-runtime"),
		}
		for _, c := range candidates {
			if st, err := os.Stat(c); err == nil && st.IsDir() {
				runtimeDir = c
				break
			}
		}
	}
	if runtimeDir == "" {
		return nil
	}

	env := []string{"AUTOFIRMA_QT_RUNTIME_DIR=" + runtimeDir}
	pluginsDir := filepath.Join(runtimeDir, "plugins")
	if st, err := os.Stat(pluginsDir); err == nil && st.IsDir() {
		env = append(env, "QT_PLUGIN_PATH="+pluginsDir)
	}
	switch runtime.GOOS {
	case "linux":
		libDir := filepath.Join(runtimeDir, "lib")
		env = append(env, "LD_LIBRARY_PATH="+libDir+":"+runtimeDir+":${LD_LIBRARY_PATH}")
	case "darwin":
		libDir := filepath.Join(runtimeDir, "lib")
		env = append(env, "DYLD_LIBRARY_PATH="+libDir+":"+runtimeDir+":${DYLD_LIBRARY_PATH}")
	}
	return env
}
