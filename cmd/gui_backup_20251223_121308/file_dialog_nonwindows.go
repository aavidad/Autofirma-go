//go:build !windows
// +build !windows

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

func selectPDFWithSystemDialog(title string) (string, error) {
	out, err := exec.Command("zenity", "--file-selection", "--file-filter=*.pdf", "--title="+title).Output()
	if err == nil {
		return strings.TrimSpace(string(out)), nil
	}

	out, err = exec.Command("kdialog", "--getopenfilename", ".", "*.pdf").Output()
	if err != nil {
		return "", fmt.Errorf("instale zenity o kdialog")
	}
	return strings.TrimSpace(string(out)), nil
}
