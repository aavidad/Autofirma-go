// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"fmt"
	"strconv"
	"strings"
)

type startLegacyServiceInvoker func(s *WebSocketServer, ports []int) error

var startLegacyServiceFunc startLegacyServiceInvoker

func (s *WebSocketServer) processServiceRequest(state *ProtocolState) string {
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

func parsePortsList(raw string) ([]int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty")
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
