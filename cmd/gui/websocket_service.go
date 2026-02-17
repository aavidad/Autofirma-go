// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"fmt"
	"log"
	"strconv"
	"strings"
)

type startLegacyServiceInvoker func(s *WebSocketServer, ports []int) error

var startLegacyServiceFunc startLegacyServiceInvoker

func (s *WebSocketServer) processServiceRequest(state *ProtocolState) string {
	notifyIfInsecureJavaScriptVersion(state.Params)

	requestedVersion := parseRequestedProtocolVersionWithDefault(state.Params, 3)
	if !isSupportedServiceProtocolVersion(requestedVersion) {
		return s.formatError("ERROR_UNSUPPORTED_PROCEDURE", fmt.Sprintf("Version de protocolo no soportada: %d", requestedVersion))
	}
	s.setServiceProtocolVersion(requestedVersion)

	portsRaw := getQueryParam(state.Params, "ports", "port", "portsList")
	if portsRaw == "" {
		return s.formatError("ERROR_PARSING_URI", "No se ha proporcionado listado de puertos")
	}
	ports, err := parsePortsList(portsRaw)
	if err != nil {
		return s.formatError("ERROR_PARSING_URI", "Listado de puertos invalido")
	}
	invoke := startLegacyServiceFunc
	if invoke == nil {
		invoke = func(srv *WebSocketServer, p []int) error {
			return srv.startLegacyService(p)
		}
	}
	if err := invoke(s, ports); err != nil {
		return "SAF_45: No se pudo abrir el servicio de socket seguro"
	}

	if sid := getQueryParam(state.Params, "idsession", "idSession"); sid != "" && strings.TrimSpace(s.session) == "" {
		s.session = sid
	}
	return "OK"
}

func (s *WebSocketServer) processWebSocketLaunchRequest(state *ProtocolState) string {
	notifyIfInsecureJavaScriptVersion(state.Params)

	requestedVersion := parseRequestedProtocolVersionWithDefault(state.Params, 4)
	if !isSupportedWebSocketProtocolVersion(requestedVersion) {
		return s.formatError("ERROR_UNSUPPORTED_PROCEDURE", fmt.Sprintf("Version de protocolo no soportada: %d", requestedVersion))
	}

	if sid := getQueryParam(state.Params, "idsession", "idSession"); sid != "" && strings.TrimSpace(s.session) == "" {
		s.session = sid
	}
	if portsRaw := getQueryParam(state.Params, "ports", "port", "portsList"); portsRaw != "" {
		if _, err := parsePortsList(portsRaw); err != nil {
			return s.formatError("ERROR_PARSING_URI", "Listado de puertos invalido")
		}
	}
	return "OK"
}

func parseRequestedProtocolVersion(params map[string][]string) int {
	return parseRequestedProtocolVersionWithDefault(params, 1)
}

func parseRequestedProtocolVersionWithDefault(params map[string][]string, def int) int {
	if params == nil {
		return def
	}
	raw := strings.TrimSpace(getQueryParam(params, "v", "ver"))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return n
}

func isSupportedWebSocketProtocolVersion(v int) bool {
	switch v {
	case 3, 4:
		return true
	default:
		return false
	}
}

func isSupportedServiceProtocolVersion(v int) bool {
	switch v {
	case 1, 2, 3:
		return true
	default:
		return false
	}
}

func parseJavaScriptVersionWithDefault(params map[string][]string, def int) int {
	if params == nil {
		return def
	}
	raw := strings.TrimSpace(getQueryParam(params, "jvc"))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return n
}

func notifyIfInsecureJavaScriptVersion(params map[string][]string) {
	if parseJavaScriptVersionWithDefault(params, 1) < 1 {
		log.Printf("[Protocol] JavaScript version code below secure minimum (jvc<1)")
	}
}

func (s *WebSocketServer) setServiceProtocolVersion(v int) {
	s.serviceMux.Lock()
	s.serviceProtocolVer = v
	s.serviceMux.Unlock()
}

func (s *WebSocketServer) getServiceProtocolVersion() int {
	s.serviceMux.Lock()
	defer s.serviceMux.Unlock()
	if s.serviceProtocolVer <= 0 {
		return 1
	}
	return s.serviceProtocolVer
}

func parsePortsList(raw string) ([]int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("vacío")
	}
	parts := strings.Split(raw, ",")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 65535 {
			return nil, fmt.Errorf("invalid port")
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no ports")
	}
	return out, nil
}
