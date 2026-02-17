// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"autofirma-host/pkg/protocol"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

func protocolSelectCertDialog(certs []protocol.Certificate) (int, bool, error) {
	if len(certs) == 0 {
		return -1, false, fmt.Errorf("no certificates")
	}
	switch runtime.GOOS {
	case "windows":
		return protocolSelectCertDialogWindows(certs)
	case "darwin":
		return protocolSelectCertDialogMac(certs)
	default:
		return protocolSelectCertDialogLinux(certs)
	}
}

func protocolSaveDialog(defaultPath string, exts string) (string, bool, error) {
	defaultPath = strings.TrimSpace(defaultPath)
	switch runtime.GOOS {
	case "windows":
		if selectedPath, canceled, err := nativeSaveFileDialogWindows("Guardar fichero", defaultPath, exts); err == nil {
			return selectedPath, canceled, nil
		}
		filter := buildWindowsFileDialogFilter(exts)
		ps := "$ErrorActionPreference='Stop'; " +
			"Add-Type -AssemblyName System.Windows.Forms; " +
			"$dlg = New-Object System.Windows.Forms.SaveFileDialog; " +
			"$dlg.Title = 'Guardar fichero'; " +
			"$dlg.FileName = '" + psQuote(defaultPath) + "'; " +
			"$dlg.Filter = '" + psQuote(filter) + "'; " +
			"if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $dlg.FileName }"
		cmd := exec.Command("powershell", "-NoProfile", "-STA", "-NonInteractive", "-Command", ps)
		configureGUICommand(cmd)
		out, err := cmd.Output()
		if err != nil {
			return "", false, err
		}
		v := strings.TrimSpace(string(out))
		if v == "" {
			return "", true, nil
		}
		return v, false, nil
	case "darwin":
		script := "set p to POSIX path of (choose file name with prompt \"Guardar fichero\" default name \"" + osaQuote(defaultPath) + "\")"
		cmd := exec.Command("osascript", "-e", script)
		configureGUICommand(cmd)
		out, err := cmd.Output()
		if err != nil {
			if isDialogCancelErr(err) {
				return "", true, nil
			}
			return "", false, err
		}
		v := strings.TrimSpace(string(out))
		if v == "" {
			return "", true, nil
		}
		return v, false, nil
	default:
		cmd := exec.Command("zenity", "--file-selection", "--save", "--confirm-overwrite", "--filename="+defaultPath, "--title=Guardar fichero")
		configureGUICommand(cmd)
		out, err := cmd.Output()
		if err == nil {
			v := strings.TrimSpace(string(out))
			if v == "" {
				return "", true, nil
			}
			return v, false, nil
		}
		if isDialogCancelErr(err) {
			return "", true, nil
		}

		cmd = exec.Command("kdialog", "--getsavefilename", defaultPath)
		configureGUICommand(cmd)
		out, err = cmd.Output()
		if err != nil {
			if isDialogCancelErr(err) {
				return "", true, nil
			}
			return "", false, err
		}
		v := strings.TrimSpace(string(out))
		if v == "" {
			return "", true, nil
		}
		return v, false, nil
	}
}

func protocolLoadDialog(initialPath string, exts string, multi bool) ([]string, bool, error) {
	initialPath = strings.TrimSpace(initialPath)
	switch runtime.GOOS {
	case "windows":
		if selectedPaths, canceled, err := nativeOpenFileDialogWindows("Seleccionar fichero", initialPath, exts, multi); err == nil {
			return selectedPaths, canceled, nil
		}
		filter := buildWindowsFileDialogFilter(exts)
		multiFlag := "$false"
		if multi {
			multiFlag = "$true"
		}
		ps := "$ErrorActionPreference='Stop'; " +
			"Add-Type -AssemblyName System.Windows.Forms; " +
			"$dlg = New-Object System.Windows.Forms.OpenFileDialog; " +
			"$dlg.Title = 'Seleccionar fichero'; " +
			"$dlg.InitialDirectory = '" + psQuote(initialPath) + "'; " +
			"$dlg.Filter = '" + psQuote(filter) + "'; " +
			"$dlg.Multiselect = " + multiFlag + "; " +
			"if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { " +
			"if ($dlg.Multiselect) { $dlg.FileNames -join '|' } else { $dlg.FileName } }"
		cmd := exec.Command("powershell", "-NoProfile", "-STA", "-NonInteractive", "-Command", ps)
		configureGUICommand(cmd)
		out, err := cmd.Output()
		if err != nil {
			return nil, false, err
		}
		v := strings.TrimSpace(string(out))
		if v == "" {
			return nil, true, nil
		}
		return splitLoadPaths(v), false, nil
	case "darwin":
		if multi {
			script := "set xs to choose file with prompt \"Seleccionar ficheros\" with multiple selections allowed\nset out to \"\"\nrepeat with f in xs\nset p to POSIX path of f\nif out is \"\" then\nset out to p\nelse\nset out to out & \"|\" & p\nend if\nend repeat\nreturn out"
			cmd := exec.Command("osascript", "-e", script)
			configureGUICommand(cmd)
			out, err := cmd.Output()
			if err != nil {
				if isDialogCancelErr(err) {
					return nil, true, nil
				}
				return nil, false, err
			}
			v := strings.TrimSpace(string(out))
			if v == "" {
				return nil, true, nil
			}
			return splitLoadPaths(v), false, nil
		}
		cmd := exec.Command("osascript", "-e", "set p to POSIX path of (choose file with prompt \"Seleccionar fichero\")")
		configureGUICommand(cmd)
		out, err := cmd.Output()
		if err != nil {
			if isDialogCancelErr(err) {
				return nil, true, nil
			}
			return nil, false, err
		}
		v := strings.TrimSpace(string(out))
		if v == "" {
			return nil, true, nil
		}
		return []string{v}, false, nil
	default:
		args := []string{"--file-selection", "--title=Seleccionar fichero"}
		if multi {
			args = append(args, "--multiple", "--separator=|")
		}
		if strings.TrimSpace(exts) != "" {
			args = append(args, "--file-filter=*."+strings.TrimPrefix(strings.TrimSpace(strings.Split(exts, ",")[0]), "."))
		}
		cmd := exec.Command("zenity", args...)
		configureGUICommand(cmd)
		out, err := cmd.Output()
		if err == nil {
			v := strings.TrimSpace(string(out))
			if v == "" {
				return nil, true, nil
			}
			if multi {
				return splitLoadPaths(v), false, nil
			}
			return []string{v}, false, nil
		}
		if isDialogCancelErr(err) {
			return nil, true, nil
		}

		kargs := []string{"--getopenfilename", initialPath}
		if multi {
			kargs = append(kargs, "--multiple", "--separate-output")
		}
		cmd = exec.Command("kdialog", kargs...)
		configureGUICommand(cmd)
		out, err = cmd.Output()
		if err != nil {
			if isDialogCancelErr(err) {
				return nil, true, nil
			}
			return nil, false, err
		}
		v := strings.TrimSpace(string(out))
		if v == "" {
			return nil, true, nil
		}
		if multi {
			lines := strings.Split(v, "\n")
			items := make([]string, 0, len(lines))
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" {
					items = append(items, line)
				}
			}
			if len(items) == 0 {
				return nil, true, nil
			}
			return items, false, nil
		}
		return []string{v}, false, nil
	}
}

func protocolSelectCertDialogLinux(certs []protocol.Certificate) (int, bool, error) {
	args := []string{"--list", "--title=Seleccionar certificado", "--column=IDX", "--column=Certificado"}
	for i := range certs {
		args = append(args, strconv.Itoa(i), certificateDisplayLabel(certs[i]))
	}
	cmd := exec.Command("zenity", args...)
	configureGUICommand(cmd)
	out, err := cmd.Output()
	if err == nil {
		v := strings.TrimSpace(string(out))
		if v == "" {
			return -1, true, nil
		}
		idx, convErr := strconv.Atoi(v)
		if convErr != nil {
			return -1, false, convErr
		}
		return idx, false, nil
	}
	if isDialogCancelErr(err) {
		return -1, true, nil
	}

	kargs := []string{"--menu", "Seleccionar certificado"}
	for i := range certs {
		kargs = append(kargs, strconv.Itoa(i), certificateDisplayLabel(certs[i]))
	}
	cmd = exec.Command("kdialog", kargs...)
	configureGUICommand(cmd)
	out, err = cmd.Output()
	if err != nil {
		if isDialogCancelErr(err) {
			return -1, true, nil
		}
		return -1, false, err
	}
	v := strings.TrimSpace(string(out))
	if v == "" {
		return -1, true, nil
	}
	idx, convErr := strconv.Atoi(v)
	if convErr != nil {
		return -1, false, convErr
	}
	return idx, false, nil
}

func protocolSelectCertDialogMac(certs []protocol.Certificate) (int, bool, error) {
	items := make([]string, 0, len(certs))
	for i := range certs {
		items = append(items, "\""+osaQuote(fmt.Sprintf("%d|%s", i, certificateDisplayLabel(certs[i])))+"\"")
	}
	script := "choose from list {" + strings.Join(items, ",") + "} with prompt \"Seleccionar certificado\""
	cmd := exec.Command("osascript", "-e", script)
	configureGUICommand(cmd)
	out, err := cmd.Output()
	if err != nil {
		if isDialogCancelErr(err) {
			return -1, true, nil
		}
		return -1, false, err
	}
	v := strings.TrimSpace(string(out))
	if v == "" || strings.EqualFold(v, "false") {
		return -1, true, nil
	}
	parts := strings.SplitN(v, "|", 2)
	idx, convErr := strconv.Atoi(strings.TrimSpace(parts[0]))
	if convErr != nil {
		return -1, false, convErr
	}
	return idx, false, nil
}

func protocolSelectCertDialogWindows(certs []protocol.Certificate) (int, bool, error) {
	entries := make([]string, 0, len(certs))
	for i := range certs {
		entries = append(entries, psQuote(fmt.Sprintf("%d|%s", i, certificateDisplayLabel(certs[i]))))
	}
	ps := "$ErrorActionPreference='Stop'; " +
		"Add-Type -AssemblyName System.Windows.Forms; " +
		"$form = New-Object System.Windows.Forms.Form; " +
		"$form.Text='Seleccionar certificado'; $form.Width=900; $form.Height=500; $form.StartPosition='CenterScreen'; " +
		"$list = New-Object System.Windows.Forms.ListBox; $list.Dock='Fill'; " +
		"$ok = New-Object System.Windows.Forms.Button; $ok.Text='Aceptar'; $ok.Dock='Bottom'; $ok.Height=36; " +
		"$cancel = New-Object System.Windows.Forms.Button; $cancel.Text='Cancelar'; $cancel.Dock='Bottom'; $cancel.Height=36; " +
		"$items = @('" + strings.Join(entries, "','") + "'); " +
		"foreach ($it in $items) { [void]$list.Items.Add($it) }; " +
		"$list.SelectedIndex = 0; " +
		"$ok.Add_Click({ if ($list.SelectedItem -ne $null) { Write-Output $list.SelectedItem; $form.Close() } }); " +
		"$cancel.Add_Click({ $form.Close() }); " +
		"$form.Controls.Add($list); $form.Controls.Add($ok); $form.Controls.Add($cancel); " +
		"[void]$form.ShowDialog()"
	cmd := exec.Command("powershell", "-NoProfile", "-STA", "-NonInteractive", "-Command", ps)
	configureGUICommand(cmd)
	out, err := cmd.Output()
	if err != nil {
		return -1, false, err
	}
	v := strings.TrimSpace(string(out))
	if v == "" {
		return -1, true, nil
	}
	parts := strings.SplitN(v, "|", 2)
	idx, convErr := strconv.Atoi(strings.TrimSpace(parts[0]))
	if convErr != nil {
		return -1, false, convErr
	}
	return idx, false, nil
}

func buildWindowsFileDialogFilter(exts string) string {
	exts = strings.TrimSpace(exts)
	if exts == "" {
		return "All files (*.*)|*.*"
	}
	parts := strings.Split(exts, ",")
	patterns := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(strings.TrimPrefix(p, "."))
		if p == "" {
			continue
		}
		patterns = append(patterns, "*."+p)
	}
	if len(patterns) == 0 {
		return "All files (*.*)|*.*"
	}
	return "Allowed files (" + strings.Join(patterns, ";") + ")|" + strings.Join(patterns, ";") + "|All files (*.*)|*.*"
}

func isDialogCancelErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	return strings.Contains(msg, "exit status 1") ||
		strings.Contains(msg, "exit status 255") ||
		strings.Contains(msg, "user canceled") ||
		strings.Contains(msg, "cancelled")
}

func osaQuote(s string) string {
	return strings.ReplaceAll(s, "\"", "\\\"")
}
