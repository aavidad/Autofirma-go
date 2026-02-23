// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var chromiumAllowlistIDPattern = regexp.MustCompile(`^[a-p]{32}$`)

type nativeAllowlistCLIConfig struct {
	ChromiumIDs []string `json:"chromium_ids"`
	FirefoxIDs  []string `json:"firefox_ids"`
	Require     bool     `json:"require_match"`
}

func maybeRunAllowlistCLI(op, idType, id, requireRaw, pathOverride string) (bool, error) {
	op = strings.ToLower(strings.TrimSpace(op))
	if op == "" {
		return false, nil
	}

	cfgPath, err := resolveAllowlistPath(pathOverride)
	if err != nil {
		return true, err
	}
	cfg, err := readAllowlistFile(cfgPath)
	if err != nil {
		return true, err
	}

	switch op {
	case "list", "listar":
		return true, printAllowlist(cfgPath, cfg)
	case "add", "añadir", "anadir":
		return true, allowlistAdd(cfgPath, cfg, idType, id)
	case "remove", "del", "delete", "eliminar", "borrar":
		return true, allowlistRemove(cfgPath, cfg, idType, id)
	case "set-require", "require":
		return true, allowlistSetRequire(cfgPath, cfg, requireRaw)
	default:
		return true, fmt.Errorf("operación de allowlist no soportada: %s", op)
	}
}

func resolveAllowlistPath(pathOverride string) (string, error) {
	if p := strings.TrimSpace(pathOverride); p != "" {
		return p, nil
	}
	if p := strings.TrimSpace(os.Getenv("AUTOFIRMA_NATIVE_ALLOWLIST_FILE")); p != "" {
		return p, nil
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "native_messaging_allowlist.json"), nil
	}
	return "/opt/autofirma-dipgra/native_messaging_allowlist.json", nil
}

func readAllowlistFile(path string) (*nativeAllowlistCLIConfig, error) {
	cfg := &nativeAllowlistCLIConfig{
		ChromiumIDs: []string{},
		FirefoxIDs:  []string{},
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("no se pudo leer allowlist (%s): %w", path, err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return cfg, nil
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("allowlist JSON inválida (%s): %w", path, err)
	}
	cfg.ChromiumIDs = normalizeIDs(cfg.ChromiumIDs)
	cfg.FirefoxIDs = normalizeIDs(cfg.FirefoxIDs)
	return cfg, nil
}

func printAllowlist(path string, cfg *nativeAllowlistCLIConfig) error {
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("Allowlist: %s\n%s\n", path, string(out))
	return nil
}

func allowlistAdd(path string, cfg *nativeAllowlistCLIConfig, idType string, id string) error {
	idType = normalizeAllowlistType(idType)
	id = strings.ToLower(strings.TrimSpace(id))
	if err := validateAllowlistID(idType, id); err != nil {
		return err
	}
	switch idType {
	case "chromium":
		cfg.ChromiumIDs = addUniqueID(cfg.ChromiumIDs, id)
	case "firefox":
		cfg.FirefoxIDs = addUniqueID(cfg.FirefoxIDs, id)
	default:
		return fmt.Errorf("tipo inválido: %s (use chromium|firefox)", idType)
	}
	return writeAllowlistAndPrint(path, cfg)
}

func allowlistRemove(path string, cfg *nativeAllowlistCLIConfig, idType string, id string) error {
	idType = normalizeAllowlistType(idType)
	id = strings.ToLower(strings.TrimSpace(id))
	if id == "" {
		return fmt.Errorf("falta -allowlist-id")
	}
	switch idType {
	case "chromium":
		cfg.ChromiumIDs = removeID(cfg.ChromiumIDs, id)
	case "firefox":
		cfg.FirefoxIDs = removeID(cfg.FirefoxIDs, id)
	default:
		return fmt.Errorf("tipo inválido: %s (use chromium|firefox)", idType)
	}
	return writeAllowlistAndPrint(path, cfg)
}

func allowlistSetRequire(path string, cfg *nativeAllowlistCLIConfig, requireRaw string) error {
	requireRaw = strings.TrimSpace(requireRaw)
	if requireRaw == "" {
		return fmt.Errorf("falta -allowlist-require true|false")
	}
	v, err := strconv.ParseBool(requireRaw)
	if err != nil {
		return fmt.Errorf("valor inválido de require: %s", requireRaw)
	}
	cfg.Require = v
	return writeAllowlistAndPrint(path, cfg)
}

func writeAllowlistAndPrint(path string, cfg *nativeAllowlistCLIConfig) error {
	cfg.ChromiumIDs = normalizeIDs(cfg.ChromiumIDs)
	cfg.FirefoxIDs = normalizeIDs(cfg.FirefoxIDs)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("no se pudo crear directorio de allowlist: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("no se pudo guardar allowlist (%s): %w", path, err)
	}
	return printAllowlist(path, cfg)
}

func normalizeAllowlistType(in string) string {
	v := strings.ToLower(strings.TrimSpace(in))
	switch v {
	case "chromium", "chrome", "edge", "brave":
		return "chromium"
	case "firefox", "ff":
		return "firefox"
	default:
		return v
	}
}

func validateAllowlistID(idType, id string) error {
	if id == "" {
		return fmt.Errorf("falta -allowlist-id")
	}
	switch idType {
	case "chromium":
		if !chromiumAllowlistIDPattern.MatchString(id) {
			return fmt.Errorf("ID Chromium inválido: %s (debe tener 32 letras a-p)", id)
		}
	case "firefox":
		// Firefox IDs suelen ser tipo extension@dominio.
		if !strings.Contains(id, "@") {
			return fmt.Errorf("ID Firefox inválido: %s (se espera formato tipo extension@dominio)", id)
		}
	default:
		return fmt.Errorf("falta -allowlist-type chromium|firefox")
	}
	return nil
}

func normalizeIDs(ids []string) []string {
	uniq := map[string]struct{}{}
	for _, raw := range ids {
		id := strings.ToLower(strings.TrimSpace(raw))
		if id == "" {
			continue
		}
		uniq[id] = struct{}{}
	}
	out := make([]string, 0, len(uniq))
	for id := range uniq {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func addUniqueID(ids []string, id string) []string {
	ids = append(ids, id)
	return normalizeIDs(ids)
}

func removeID(ids []string, id string) []string {
	out := make([]string, 0, len(ids))
	for _, raw := range ids {
		v := strings.ToLower(strings.TrimSpace(raw))
		if v == "" || v == id {
			continue
		}
		out = append(out, v)
	}
	return normalizeIDs(out)
}
