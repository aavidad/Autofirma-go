//go:build !windows
// +build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func getSettingsPath() string {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		cfgDir = filepath.Join(os.TempDir(), "AutofirmaDipgra")
	}
	return filepath.Join(cfgDir, "Diputacion de Granada", "AutoFirma Dipgra.conf")
}

func LoadUserSettings() UserSettings {
	s := UserSettings{}
	b, err := os.ReadFile(getSettingsPath())
	if err == nil {
		lines := strings.Split(string(b), "\n")
		inGeneral := false
		for _, line := range lines {
			l := strings.TrimSpace(line)
			if strings.HasPrefix(l, "[") {
				inGeneral = strings.HasPrefix(l, "[General]")
				continue
			}
			if inGeneral && strings.Contains(l, "=") {
				parts := strings.SplitN(l, "=", 2)
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				switch key {
				case "expertMode":
					s.ExpertMode = val == "true"
				case "themeIndex":
					if i, err := strconv.Atoi(val); err == nil {
						s.ThemeIndex = i
					}
				case "autoClose":
					s.AutoClose = val == "true"
				case "stickySigner":
					s.StickySigner = val == "true"
				case "certsExpiredShow":
					s.CertsExpiredShow = val == "true"
				case "tsaEnabled":
					s.TsaEnabled = val == "true"
				case "tsaUrl":
					s.TsaUrl = val
				case "proxyEnabled":
					s.ProxyEnabled = val == "true"
				case "proxyHost":
					s.ProxyHost = val
				case "proxyPort":
					if i, err := strconv.Atoi(val); err == nil {
						s.ProxyPort = i
					}
				}
			}
		}
	}
	return s
}

func SaveUserSettings(s UserSettings) error {
	path := getSettingsPath()
	os.MkdirAll(filepath.Dir(path), 0700)

	b, err := os.ReadFile(path)

	boolToStr := func(v bool) string {
		if v {
			return "true"
		}
		return "false"
	}

	writeGeneral := func(newLines []string) []string {
		newLines = append(newLines, "[General]")
		newLines = append(newLines, "expertMode="+boolToStr(s.ExpertMode))
		newLines = append(newLines, "themeIndex="+fmt.Sprintf("%d", s.ThemeIndex))
		newLines = append(newLines, "autoClose="+boolToStr(s.AutoClose))
		newLines = append(newLines, "stickySigner="+boolToStr(s.StickySigner))
		newLines = append(newLines, "certsExpiredShow="+boolToStr(s.CertsExpiredShow))
		newLines = append(newLines, "tsaEnabled="+boolToStr(s.TsaEnabled))
		newLines = append(newLines, "tsaUrl="+s.TsaUrl)
		newLines = append(newLines, "proxyEnabled="+boolToStr(s.ProxyEnabled))
		newLines = append(newLines, "proxyHost="+s.ProxyHost)
		newLines = append(newLines, "proxyPort="+fmt.Sprintf("%d", s.ProxyPort))
		return newLines
	}

	content := ""
	if err == nil {
		lines := strings.Split(string(b), "\n")
		var newLines []string
		skipGeneral := false
		foundGeneral := false
		for _, l := range lines {
			t := strings.TrimSpace(l)
			if strings.HasPrefix(t, "[") {
				if strings.HasPrefix(t, "[General]") {
					skipGeneral = true
					foundGeneral = true
					newLines = writeGeneral(newLines)
				} else {
					skipGeneral = false
					newLines = append(newLines, l)
				}
			} else if !skipGeneral {
				newLines = append(newLines, l)
			}
		}
		if !foundGeneral {
			newLines = append(newLines, "\n")
			newLines = writeGeneral(newLines)
		}
		content = strings.Join(newLines, "\n")
	} else {
		content = strings.Join(writeGeneral(nil), "\n") + "\n"
	}

	return os.WriteFile(path, []byte(content), 0600)
}
