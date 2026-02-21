// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"autofirma-host/pkg/version"
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
	finalBin, err := ensureAppInFolder(m.binPath)
	if err != nil {
		return fmt.Errorf("error preparando app portable: %v", err)
	}
	m.binPath = finalBin
	WriteUpdaterConfig(version.CurrentVersion)

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
	finalBin, err := ensureAppInFolder(m.binPath)
	if err != nil {
		return fmt.Errorf("error preparando app portable: %v", err)
	}
	m.binPath = finalBin
	WriteUpdaterConfig(version.CurrentVersion)

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

const runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`
const runKeyName = "AutoFirmaDipgra"

func (m *windowsServiceMgr) Status() ServiceStatus {
	st := ServiceStatus{Platform: "windows", Method: "registry", BinPath: m.binPath}

	// Check registry
	out, err := exec.Command("reg", "query", `HKCU\`+runKeyPath, "/v", runKeyName).CombinedOutput()
	if err == nil && strings.Contains(string(out), runKeyName) {
		st.Installed = true
		// Pobre parsing de la salida de reg query para el path del binario
		lines := strings.Split(string(out), "\n")
		for _, l := range lines {
			if strings.Contains(l, runKeyName) {
				parts := strings.SplitN(l, "REG_SZ", 2)
				if len(parts) == 2 {
					val := strings.TrimSpace(parts[1])
					st.BinPath = strings.Trim(strings.Fields(val)[0], "\"")
				}
			}
		}
	}

	// Check if running
	outTaskList, err := exec.Command("tasklist", "/FI", "IMAGENAME eq autofirma-desktop.exe").Output()
	if err == nil && strings.Contains(string(outTaskList), "autofirma-desktop.exe") {
		st.Running = true
	}

	return st
}

func (m *windowsServiceMgr) Install(ipcSocket string) error {
	finalBin, err := ensureAppInFolder(m.binPath)
	if err != nil {
		return fmt.Errorf("error preparando app portable: %v", err)
	}
	m.binPath = finalBin
	WriteUpdaterConfig(version.CurrentVersion)

	if ipcSocket == "" {
		ipcSocket = `\\.\pipe\autofirma_ipc`
	}

	cmdStr := fmt.Sprintf(`"%s" --ipc`, m.binPath)
	if err := exec.Command("reg", "add", `HKCU\`+runKeyPath, "/v", runKeyName, "/t", "REG_SZ", "/d", cmdStr, "/f").Run(); err != nil {
		return fmt.Errorf("error escribiendo registro: %v", err)
	}

	return m.Start()
}

func (m *windowsServiceMgr) Uninstall() error {
	m.Stop()
	exec.Command("reg", "delete", `HKCU\`+runKeyPath, "/v", runKeyName, "/f").Run()
	return nil
}

func (m *windowsServiceMgr) Start() error {
	cmd := exec.Command(m.binPath, "--ipc")
	return cmd.Start()
}

func (m *windowsServiceMgr) Stop() error {
	exec.Command("taskkill", "/f", "/im", "autofirma-desktop.exe").Run()
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

// ensureAppInFolder checks if the current executable is running from the permanent
// application folder. If not, it copies it there and returns the new absolute path.
func ensureAppInFolder(currentBin string) (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return currentBin, fmt.Errorf("could not get config dir: %v", err)
	}

	appDir := filepath.Join(configDir, "AutoFirmaDipgra", "bin")
	if err := os.MkdirAll(appDir, 0755); err != nil {
		return currentBin, fmt.Errorf("could not create app dir: %v", err)
	}

	binName := filepath.Base(currentBin)
	targetBin := filepath.Join(appDir, binName)

	if currentBin == targetBin {
		return targetBin, nil
	}

	srcFile, err := os.Open(currentBin)
	if err != nil {
		return currentBin, fmt.Errorf("could not open source binary: %v", err)
	}
	defer srcFile.Close()

	os.Remove(targetBin)

	dstFile, err := os.OpenFile(targetBin, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return currentBin, fmt.Errorf("could not create target binary: %v", err)
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return currentBin, fmt.Errorf("error copying binary: %v", err)
	}

	if runtime.GOOS != "windows" {
		os.Chmod(targetBin, 0755)
	}

	return targetBin, nil
}

type UpdaterConfig struct {
	Version   string `json:"version"`
	UpdateURL string `json:"updateUrl"`
	Platform  string `json:"platform"`
}

const updateCheckURL = "https://autofirma.dipgra.es/version.json"

func WriteUpdaterConfig(version string) error {
	cfg := UpdaterConfig{
		Version:   version,
		UpdateURL: updateCheckURL,
		Platform:  runtime.GOOS,
	}

	if runtime.GOOS == "windows" {
		// Emulamos acceso al registro llamando a reg.exe para no requerir build-tags en este fichero compartido
		cmd1 := exec.Command("reg", "add", `HKCU\Software\AutoFirmaDipgra`, "/v", "Version", "/t", "REG_SZ", "/d", cfg.Version, "/f")
		cmd2 := exec.Command("reg", "add", `HKCU\Software\AutoFirmaDipgra`, "/v", "UpdateURL", "/t", "REG_SZ", "/d", cfg.UpdateURL, "/f")
		err1 := cmd1.Run()
		err2 := cmd2.Run()
		if err1 != nil || err2 != nil {
			return fmt.Errorf("error escribiendo registro: %v, %v", err1, err2)
		}
		return nil
	}

	configDir, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	appConfigDir := filepath.Join(configDir, "AutoFirmaDipgra")
	os.MkdirAll(appConfigDir, 0755)

	file := filepath.Join(appConfigDir, "updater.json")
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(file, data, 0644)
}
