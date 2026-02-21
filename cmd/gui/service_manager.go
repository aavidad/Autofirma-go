// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ServiceStatus describes the state of the user-level background service.
type ServiceStatus struct {
	Installed bool   `json:"installed"`
	Running   bool   `json:"running"`
	Platform  string `json:"platform"`
	Method    string `json:"method"` // "systemd", "launchagent", "registry", "taskscheduler"
	BinPath   string `json:"binPath"`
}

const serviceName = "autofirma-backend"
const serviceLabel = "es.dipgra.autofirma.backend"
const serviceDescription = "AutoFirma Backend - motor de firma digital de la Diputación de Granada"

// GetServiceManager returns the platform-appropriate manager.
func GetServiceManager() (svcMgr, error) {
	coreBin, err := findCoreBackendBinary()
	if err != nil {
		return nil, fmt.Errorf("no se encontró el binario del backend: %w", err)
	}

	switch runtime.GOOS {
	case "linux":
		return &linuxServiceMgr{binPath: coreBin}, nil
	case "darwin":
		return &macServiceMgr{binPath: coreBin}, nil
	case "windows":
		return &windowsServiceMgr{binPath: coreBin}, nil
	default:
		return nil, fmt.Errorf("plataforma no soportada: %s", runtime.GOOS)
	}
}

// findCoreBackendBinary looks for the autofirma-desktop core binary.
// It searches next to the current executable, parent dirs, and PATH.
// This avoids installing the GUI binary (-gio, -qt, etc.) as a service.
func findCoreBackendBinary() (string, error) {
	self, _ := os.Executable()
	self, _ = filepath.EvalSymlinks(self)
	selfDir := filepath.Dir(self)

	coreName := "autofirma-desktop"
	if runtime.GOOS == "windows" {
		coreName += ".exe"
	}

	candidates := []string{
		// Same dir as current binary
		filepath.Join(selfDir, coreName),
		// One level up (e.g. installed layout: bin/ next to GUI binary)
		filepath.Join(selfDir, "..", coreName),
		// Two levels up
		filepath.Join(selfDir, "..", "..", coreName),
	}

	// Also try PATH
	if inPath, err := exec.LookPath(coreName); err == nil {
		candidates = append(candidates, inPath)
	}

	for _, c := range candidates {
		abs, err := filepath.Abs(c)
		if err != nil {
			continue
		}
		if _, err := os.Stat(abs); err == nil {
			return abs, nil
		}
	}

	// Last resort: if THIS binary doesn't have a well-known suffix, assume it IS the core
	suffixes := []string{"-gio", "-qt", "-fyne", "-wails", "-gui"}
	selfBase := filepath.Base(self)
	isGUI := false
	for _, s := range suffixes {
		if strings.HasSuffix(selfBase, s) || strings.Contains(selfBase, s+".") {
			isGUI = true
			break
		}
	}
	if !isGUI {
		return self, nil
	}

	return "", fmt.Errorf("binario '%s' no encontrado. Cópialo junto a la GUI", coreName)
}

type svcMgr interface {
	Status() ServiceStatus
	Install(ipcSocket string) error
	Uninstall() error
	Start() error
	Stop() error
}

// ─── Linux (systemd --user) ───────────────────────────────────────────────────

type linuxServiceMgr struct{ binPath string }

func (m *linuxServiceMgr) unitPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "systemd", "user", serviceName+".service")
}

func (m *linuxServiceMgr) Status() ServiceStatus {
	st := ServiceStatus{Platform: "linux", Method: "systemd", BinPath: m.binPath}
	_, err := os.Stat(m.unitPath())
	st.Installed = err == nil
	if st.Installed {
		out, _ := exec.Command("systemctl", "--user", "is-active", serviceName).Output()
		st.Running = strings.TrimSpace(string(out)) == "active"
	}
	return st
}

func (m *linuxServiceMgr) Install(ipcSocket string) error {
	unitDir := filepath.Dir(m.unitPath())
	if err := os.MkdirAll(unitDir, 0755); err != nil {
		return err
	}
	if ipcSocket == "" {
		ipcSocket = "/tmp/autofirma_ipc.sock"
	}
	unit := fmt.Sprintf(`[Unit]
Description=%s
After=network.target

[Service]
Type=simple
ExecStart=%s --ipc --ipc-socket %s
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
`, serviceDescription, m.binPath, ipcSocket)

	if err := os.WriteFile(m.unitPath(), []byte(unit), 0644); err != nil {
		return err
	}
	exec.Command("systemctl", "--user", "daemon-reload").Run()
	return exec.Command("systemctl", "--user", "enable", "--now", serviceName).Run()
}

func (m *linuxServiceMgr) Uninstall() error {
	exec.Command("systemctl", "--user", "disable", "--now", serviceName).Run()
	exec.Command("systemctl", "--user", "daemon-reload").Run()
	return os.Remove(m.unitPath())
}

func (m *linuxServiceMgr) Start() error {
	return exec.Command("systemctl", "--user", "start", serviceName).Run()
}

func (m *linuxServiceMgr) Stop() error {
	return exec.Command("systemctl", "--user", "stop", serviceName).Run()
}

// ─── macOS (LaunchAgent) ─────────────────────────────────────────────────────

type macServiceMgr struct{ binPath string }

func (m *macServiceMgr) plistPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", serviceLabel+".plist")
}

func (m *macServiceMgr) Status() ServiceStatus {
	st := ServiceStatus{Platform: "darwin", Method: "launchagent", BinPath: m.binPath}
	_, err := os.Stat(m.plistPath())
	st.Installed = err == nil
	if st.Installed {
		out, _ := exec.Command("launchctl", "list", serviceLabel).Output()
		st.Running = strings.Contains(string(out), serviceLabel)
	}
	return st
}

func (m *macServiceMgr) Install(ipcSocket string) error {
	agentDir := filepath.Dir(m.plistPath())
	if err := os.MkdirAll(agentDir, 0755); err != nil {
		return err
	}
	if ipcSocket == "" {
		ipcSocket = "/tmp/autofirma_ipc.sock"
	}
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>--ipc</string>
        <string>--ipc-socket</string>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/autofirma-backend.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/autofirma-backend.log</string>
</dict>
</plist>
`, serviceLabel, m.binPath, ipcSocket)

	if err := os.WriteFile(m.plistPath(), []byte(plist), 0644); err != nil {
		return err
	}
	return exec.Command("launchctl", "load", "-w", m.plistPath()).Run()
}

func (m *macServiceMgr) Uninstall() error {
	exec.Command("launchctl", "unload", "-w", m.plistPath()).Run()
	return os.Remove(m.plistPath())
}

func (m *macServiceMgr) Start() error {
	return exec.Command("launchctl", "start", serviceLabel).Run()
}

func (m *macServiceMgr) Stop() error {
	return exec.Command("launchctl", "stop", serviceLabel).Run()
}

// ─── Windows (Task Scheduler al inicio de sesión) ────────────────────────────
// Usamos Task Scheduler y NO el SCM (Windows Services) porque los servicios SCM
// se ejecutan como SYSTEM y no tienen acceso al almacén de certificados del usuario.

type windowsServiceMgr struct{ binPath string }

const winTaskName = "AutoFirma Backend"

func (m *windowsServiceMgr) Status() ServiceStatus {
	st := ServiceStatus{Platform: "windows", Method: "taskscheduler", BinPath: m.binPath}
	out, err := exec.Command("schtasks", "/query", "/tn", winTaskName, "/fo", "LIST").CombinedOutput()
	if err == nil && strings.Contains(string(out), winTaskName) {
		st.Installed = true
		st.Running = strings.Contains(string(out), "Running")
	}
	return st
}

func (m *windowsServiceMgr) Install(ipcSocket string) error {
	// /sc ONLOGON runs as the current user at logon
	// /rl LIMITED ensures it does NOT run as administrator
	cmd := exec.Command("schtasks",
		"/create",
		"/tn", winTaskName,
		"/sc", "ONLOGON",
		"/rl", "LIMITED",
		"/tr", fmt.Sprintf(`"%s" --ipc`, m.binPath),
		"/f",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks error: %v: %s", err, out)
	}
	// Start it now too
	return m.Start()
}

func (m *windowsServiceMgr) Uninstall() error {
	m.Stop()
	out, err := exec.Command("schtasks", "/delete", "/tn", winTaskName, "/f").CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks delete error: %v: %s", err, out)
	}
	return nil
}

func (m *windowsServiceMgr) Start() error {
	out, err := exec.Command("schtasks", "/run", "/tn", winTaskName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

func (m *windowsServiceMgr) Stop() error {
	// Find and kill the process
	exec.Command("taskkill", "/f", "/im", filepath.Base(m.binPath)).Run()
	return nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// WaitForSocket waits up to `timeout` for the IPC socket to appear.
func WaitForSocket(socketPath string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			return true
		}
		time.Sleep(300 * time.Millisecond)
	}
	return false
}
