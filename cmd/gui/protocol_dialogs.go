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

func protocolConfirmFirstDomainUseDialog(host string) (bool, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return false, fmt.Errorf("dominio vacío")
	}
	title := "Confirmación de seguridad"
	msg := "Primera vez firmando en este sitio: " + host + ".\n\n" +
		"Solo continúa si conoces y confías en esta sede.\n\n" +
		"Riesgos si no es fiable:\n" +
		"- envío de firma/certificado a un dominio no confiable\n" +
		"- posible suplantación del servicio de firma\n" +
		"- exposición de metadatos del documento\n\n" +
		"¿Quieres permitir firma para este dominio?"
	switch runtime.GOOS {
	case "windows":
		ps := "$ErrorActionPreference='Stop'; " +
			"Add-Type -AssemblyName PresentationFramework; " +
			"$r=[System.Windows.MessageBox]::Show('" + psQuote(msg) + "','" + psQuote(title) + "','YesNo','Warning'); " +
			"if ($r -eq 'Yes') { 'YES' } else { 'NO' }"
		cmd := exec.Command("powershell", "-NoProfile", "-STA", "-NonInteractive", "-Command", ps)
		configureGUICommand(cmd)
		out, err := cmd.Output()
		if err != nil {
			return false, err
		}
		return strings.EqualFold(strings.TrimSpace(string(out)), "YES"), nil
	case "darwin":
		script := "display dialog \"" + osaQuote(msg) + "\" with title \"" + osaQuote(title) + "\" buttons {\"No\", \"Sí\"} default button \"No\" with icon caution"
		cmd := exec.Command("osascript", "-e", script)
		configureGUICommand(cmd)
		out, err := cmd.Output()
		if err != nil {
			if isDialogCancelErr(err) {
				return false, nil
			}
			return false, err
		}
		return strings.Contains(strings.ToLower(strings.TrimSpace(string(out))), "sí"), nil
	default:
		cmd := exec.Command("zenity", "--question", "--title="+title, "--text="+msg, "--ok-label=Sí, confiar", "--cancel-label=No, cancelar")
		configureGUICommand(cmd)
		err := cmd.Run()
		if err == nil {
			return true, nil
		}
		if isDialogCancelErr(err) {
			return false, nil
		}
		kcmd := exec.Command("kdialog", "--warningyesno", msg, "--title", title)
		configureGUICommand(kcmd)
		if err := kcmd.Run(); err == nil {
			return true, nil
		}
		return false, nil
	}
}

func protocolConfirmOverwriteDialog(path string) (bool, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return false, fmt.Errorf("ruta vacía")
	}
	title := "Confirmar sobrescritura"
	msg := "El fichero ya existe:\n" + path + "\n\n¿Deseas sobrescribirlo?"

	switch runtime.GOOS {
	case "windows":
		ps := "$ErrorActionPreference='Stop'; " +
			"Add-Type -AssemblyName PresentationFramework; " +
			"$r=[System.Windows.MessageBox]::Show('" + psQuote(msg) + "','" + psQuote(title) + "','YesNoCancel','Warning'); " +
			"if ($r -eq 'Yes') { 'YES' } elseif ($r -eq 'No') { 'NO' } else { 'CANCEL' }"
		cmd := exec.Command("powershell", "-NoProfile", "-STA", "-NonInteractive", "-Command", ps)
		configureGUICommand(cmd)
		out, err := cmd.Output()
		if err != nil {
			return false, err
		}
		v := strings.ToUpper(strings.TrimSpace(string(out)))
		if v == "YES" {
			return true, nil
		}
		return false, nil
	case "darwin":
		script := "display dialog \"" + osaQuote(msg) + "\" with title \"" + osaQuote(title) + "\" buttons {\"No\", \"Sí\"} default button \"No\" with icon caution"
		cmd := exec.Command("osascript", "-e", script)
		configureGUICommand(cmd)
		out, err := cmd.Output()
		if err != nil {
			if isDialogCancelErr(err) {
				return false, nil
			}
			return false, err
		}
		v := strings.ToLower(strings.TrimSpace(string(out)))
		if strings.Contains(v, "sí") {
			return true, nil
		}
		return false, nil
	default:
		cmd := exec.Command("zenity", "--question", "--title="+title, "--text="+msg, "--ok-label=Sí, sobrescribir", "--cancel-label=No, guardar con otro nombre")
		configureGUICommand(cmd)
		err := cmd.Run()
		if err == nil {
			return true, nil
		}
		if isDialogCancelErr(err) {
			return false, nil
		}
		kcmd := exec.Command("kdialog", "--warningyesnocancel", msg, "--title", title)
		configureGUICommand(kcmd)
		if err := kcmd.Run(); err == nil {
			return true, nil
		}
		if isDialogCancelErr(err) {
			return false, nil
		}
		return false, nil
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
	labels := buildCertificateDialogLabels(certs)
	args := []string{
		"--list",
		"--title=Seleccionar certificado",
		"--text=Seleccione un certificado para continuar.",
		"--ok-label=Aceptar",
		"--cancel-label=Cancelar",
		"--column=IDX",
		"--column=Certificado",
		"--hide-column=1",
		"--print-column=1",
	}
	for i := range certs {
		args = append(args, strconv.Itoa(i), labels[i])
	}
	cmd := exec.Command("zenity", args...)
	configureGUICommand(cmd)
	out, err := cmd.Output()
	if err == nil {
		v := strings.TrimSpace(string(out))
		if v == "" {
			return -1, true, nil
		}
		if idx, convErr := strconv.Atoi(v); convErr == nil {
			return idx, false, nil
		}
		for i, lbl := range labels {
			if lbl == v {
				return i, false, nil
			}
		}
		return -1, false, fmt.Errorf("selección no reconocida: %s", v)
	}
	if isDialogCancelErr(err) {
		return -1, true, nil
	}

	kargs := []string{"--menu", "Seleccionar certificado"}
	for i := range certs {
		kargs = append(kargs, strconv.Itoa(i), labels[i])
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
	labels := buildCertificateDialogLabels(certs)
	items := make([]string, 0, len(certs))
	for i := range labels {
		items = append(items, "\""+osaQuote(labels[i])+"\"")
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
	for i, lbl := range labels {
		if lbl == v {
			return i, false, nil
		}
	}
	return -1, false, fmt.Errorf("selección no reconocida: %s", v)
}

func protocolSelectCertDialogWindows(certs []protocol.Certificate) (int, bool, error) {
	labels := buildCertificateDialogLabels(certs)
	entries := make([]string, 0, len(certs))
	for i := range labels {
		entries = append(entries, psQuote(labels[i]))
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
		"$ok.Add_Click({ if ($list.SelectedIndex -ge 0) { Write-Output $list.SelectedIndex; $form.Close() } }); " +
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
	idx, convErr := strconv.Atoi(v)
	if convErr != nil {
		return -1, false, convErr
	}
	return idx, false, nil
}

func buildCertificateDialogLabels(certs []protocol.Certificate) []string {
	labels := make([]string, len(certs))
	seen := make(map[string]int, len(certs))
	for i := range certs {
		base := strings.TrimSpace(certificateDisplayLabel(certs[i]))
		if base == "" {
			base = fmt.Sprintf("Certificado %d", i+1)
		}
		count := seen[base]
		seen[base] = count + 1
		if count > 0 {
			labels[i] = fmt.Sprintf("%s (%d)", base, count+1)
		} else {
			labels[i] = base
		}
	}
	return labels
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
