//go:build windows
// +build windows

package main

import (
	"fmt"
	"log"

	"golang.org/x/sys/windows/registry"
)

func LoadUserSettings() UserSettings {
	s := UserSettings{}
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Diputacion de Granada\AutoFirma Dipgra\General`, registry.READ)
	if err == nil {
		defer k.Close()

		readBool := func(name string, target *bool) {
			val, _, err := k.GetStringValue(name)
			if err == nil {
				*target = val == "true"
			}
		}
		readInt := func(name string, target *int) {
			val, _, err := k.GetStringValue(name)
			if err == nil {
				fmt.Sscanf(val, "%d", target)
			} else {
				// try integer type
				uval, _, err := k.GetIntegerValue(name)
				if err == nil {
					*target = int(uval)
				}
			}
		}
		readString := func(name string, target *string) {
			val, _, err := k.GetStringValue(name)
			if err == nil {
				*target = val
			}
		}

		readBool("expertMode", &s.ExpertMode)
		readInt("themeIndex", &s.ThemeIndex)
		readBool("autoClose", &s.AutoClose)
		readBool("stickySigner", &s.StickySigner)
		readBool("certsExpiredShow", &s.CertsExpiredShow)
		readBool("tsaEnabled", &s.TsaEnabled)
		readString("tsaUrl", &s.TsaUrl)
		readBool("proxyEnabled", &s.ProxyEnabled)
		readString("proxyHost", &s.ProxyHost)
		readInt("proxyPort", &s.ProxyPort)
	}
	return s
}

func SaveUserSettings(s UserSettings) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Diputacion de Granada\AutoFirma Dipgra\General`, registry.ALL_ACCESS)
	if err != nil {
		k, _, err = registry.CreateKey(registry.CURRENT_USER, `Software\Diputacion de Granada\AutoFirma Dipgra\General`, registry.ALL_ACCESS)
		if err != nil {
			log.Printf("Error creating registry key: %v", err)
			return err
		}
	}
	defer k.Close()

	boolToStr := func(v bool) string {
		if v {
			return "true"
		}
		return "false"
	}

	k.SetStringValue("expertMode", boolToStr(s.ExpertMode))
	k.SetStringValue("themeIndex", fmt.Sprintf("%d", s.ThemeIndex))
	k.SetStringValue("autoClose", boolToStr(s.AutoClose))
	k.SetStringValue("stickySigner", boolToStr(s.StickySigner))
	k.SetStringValue("certsExpiredShow", boolToStr(s.CertsExpiredShow))
	k.SetStringValue("tsaEnabled", boolToStr(s.TsaEnabled))
	k.SetStringValue("tsaUrl", s.TsaUrl)
	k.SetStringValue("proxyEnabled", boolToStr(s.ProxyEnabled))
	k.SetStringValue("proxyHost", s.ProxyHost)
	k.SetStringValue("proxyPort", fmt.Sprintf("%d", s.ProxyPort))
	return nil
}
