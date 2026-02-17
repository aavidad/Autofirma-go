// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	legacyServiceReadTimeout = 1500 * time.Millisecond
	legacyResponseMaxSize    = 1000000
	legacyReadBufferSize     = 2048
	legacyBufferedSecRange   = 36
	legacyMaxReadEmptyTries  = 10
	legacyEOFMarker          = "@EOF"
)

var legacyMaxServicePayloadBytes = 32 * 1024 * 1024
var legacyMaxRawRequestBytes = 8 * 1024 * 1024
var errLegacyRequestTooLarge = errors.New("legacy request too large")

const legacyMemoryError = "MEMORY_ERROR"

type legacySocketReadResult struct {
	RequestBody string
	SessionID   string
}

func (s *WebSocketServer) startLegacyService(ports []int) error {
	s.serviceMux.Lock()
	if s.serviceListener != nil {
		s.serviceMux.Unlock()
		return nil
	}
	s.serviceMux.Unlock()

	certFile, keyFile, err := ensureLocalTLSCerts()
	if err != nil {
		return err
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{pair},
	}

	var ln net.Listener
	for _, p := range ports {
		addr := fmt.Sprintf("127.0.0.1:%d", p)
		ln, err = tls.Listen("tcp", addr, cfg)
		if err == nil {
			log.Printf("[Service] Legacy TLS socket listening on %s", addr)
			break
		}
	}
	if ln == nil {
		return fmt.Errorf("no se pudo abrir socket TLS en ningun puerto solicitado")
	}

	s.serviceMux.Lock()
	s.serviceListener = ln
	s.serviceMux.Unlock()

	go s.acceptLegacyServiceLoop(ln)
	return nil
}

func (s *WebSocketServer) acceptLegacyServiceLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go s.handleLegacyServiceConn(conn)
	}
}

func (s *WebSocketServer) handleLegacyServiceConn(conn net.Conn) {
	defer conn.Close()
	if !isLoopbackRemoteAddr(conn.RemoteAddr().String()) {
		return
	}
	readRes, err := readLegacySocketPayload(conn)
	if errors.Is(err, errLegacyRequestTooLarge) {
		_, _ = conn.Write(buildLegacyHTTPResponse(legacyMemoryError))
		return
	}
	if err != nil {
		_, _ = conn.Write(buildLegacyHTTPResponse("SAF_03: Parametros incorrectos"))
		return
	}
	if strings.TrimSpace(readRes.RequestBody) == "" {
		return
	}
	if err := s.checkLegacySessionIDValue(readRes.SessionID); err != nil {
		_, _ = conn.Write(buildLegacyHTTPResponse("SAF_03: Parametros incorrectos"))
		return
	}
	res := s.processLegacyServiceCommand(readRes.RequestBody)
	_, _ = conn.Write(buildLegacyHTTPResponse(res))
}

func readLegacySocketPayload(conn net.Conn) (legacySocketReadResult, error) {
	_ = conn.SetReadDeadline(time.Now().Add(legacyServiceReadTimeout))
	var data strings.Builder
	subFragment := ""
	buf := make([]byte, legacyReadBufferSize)
	emptyReads := 0
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			insert := string(buf[:n])
			if strings.TrimSpace(insert) == "" {
				emptyReads++
				if emptyReads > legacyMaxReadEmptyTries {
					return legacySocketReadResult{}, nil
				}
				continue
			}
			emptyReads = 0

			headLen := minInt(legacyBufferedSecRange, len(insert))
			subFragment += insert[:headLen]

			if hasLegacyEOF(subFragment) || hasLegacyEOF(insert) {
				foundOnSub := hasLegacyEOF(subFragment)
				source := insert
				if foundOnSub {
					source = subFragment
				}
				eofPos := indexLegacyEOF(source)
				lowerSource := strings.ToLower(source)
				idPos := strings.Index(lowerSource, "idsession")
				requestSessionID := extractLegacySessionID(source)

				if foundOnSub {
					if idPos >= 0 && idPos < legacyBufferedSecRange {
						trimBuilderTail(&data, legacyBufferedSecRange-idPos)
					} else if eofPos >= 0 && eofPos < legacyBufferedSecRange {
						trimBuilderTail(&data, legacyBufferedSecRange-eofPos)
					} else if idPos > 0 || eofPos > 0 {
						end := eofPos
						if idPos >= 0 {
							end = idPos
						}
						if end > 0 {
							data.WriteString(source[:end])
							if data.Len() > legacyMaxRawRequestBytes {
								return legacySocketReadResult{}, errLegacyRequestTooLarge
							}
						}
					}
				} else {
					end := eofPos
					if idPos >= 0 {
						end = idPos
					}
					if end > 0 {
						data.WriteString(insert[:end])
						if data.Len() > legacyMaxRawRequestBytes {
							return legacySocketReadResult{}, errLegacyRequestTooLarge
						}
					}
				}
				return legacySocketReadResult{
					RequestBody: data.String(),
					SessionID:   requestSessionID,
				}, nil
			}

			data.WriteString(insert)
			if data.Len() > legacyMaxRawRequestBytes {
				return legacySocketReadResult{}, errLegacyRequestTooLarge
			}
			if len(insert) > legacyBufferedSecRange {
				subFragment = insert[len(insert)-legacyBufferedSecRange:]
			} else {
				subFragment = insert
			}
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return legacySocketReadResult{
					RequestBody: data.String(),
				}, nil
			}
			return legacySocketReadResult{
				RequestBody: data.String(),
			}, err
		}
	}
}

func buildLegacyHTTPResponse(message string) []byte {
	body := base64.RawURLEncoding.EncodeToString([]byte(message))
	resp := "HTTP/1.1 200 OK\r\n" +
		"Connection: close\r\n" +
		"Pragma: no-cache\r\n" +
		"Server: AutoFirma Go\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Access-Control-Allow-Origin: *\r\n" +
		"\r\n" +
		body
	return []byte(resp)
}

func (s *WebSocketServer) processLegacyServicePayload(raw string) string {
	req := strings.TrimSpace(normalizeLegacyRequestPayload(extractLegacyPayload(raw)))
	if req == "" {
		return "SAF_03: Peticion vacia"
	}
	if err := s.checkLegacySessionID(req); err != nil {
		return "SAF_03: Parametros incorrectos"
	}
	return s.processLegacyServiceCommand(req)
}

func (s *WebSocketServer) processLegacyServiceCommand(req string) string {
	// Keep Java priority order from CommandProcessorThread:
	// cmd, echo, fragment, firm, send.
	if v, ok := extractLegacyParam(req, "cmd="); ok {
		cmd, err := decodeAutoFirmaB64(v)
		if err != nil {
			return "SAF_03: Comando cmd invalido"
		}
		uri := strings.TrimSpace(string(cmd))
		uri = ensureProtocolVersionParam(uri, s.getServiceProtocolVersion())
		uriLower := strings.ToLower(uri)
		if !strings.HasPrefix(uriLower, "afirma://") ||
			strings.HasPrefix(uriLower, "afirma://service?") ||
			strings.HasPrefix(uriLower, "afirma://service/?") {
			return "SAF_03: Comando cmd invalido"
		}
		if strings.HasPrefix(uriLower, "afirma://save?") || strings.HasPrefix(uriLower, "afirma://save/?") {
			result := s.processProtocolRequest(uri)
			if result == "SAVE_OK" || result == "OK" {
				return "SAVE_OK"
			}
			if result == "CANCEL" {
				return "CANCEL"
			}
			return "SAF_03: Parametros incorrectos"
		}
		s.serviceMux.Lock()
		alreadyPrepared := len(s.serviceResponseParts) > 0
		s.serviceMux.Unlock()
		if !alreadyPrepared {
			result := s.processProtocolRequest(uri)
			s.serviceMux.Lock()
			s.serviceResponseParts = splitLegacyResponse(result)
			total := len(s.serviceResponseParts)
			s.serviceMux.Unlock()
			if total <= 0 {
				return "0"
			}
		}
		s.serviceMux.Lock()
		total := len(s.serviceResponseParts)
		s.serviceMux.Unlock()
		return strconv.Itoa(total)
	}

	if v, ok := extractLegacyParam(req, "echo="); ok {
		if strings.Contains(v, "-") {
			s.resetLegacyServiceState()
		}
		return "OK"
	}

	if v, ok := extractLegacyParam(req, "fragment="); ok {
		parts := strings.Split(v, "@")
		if len(parts) < 4 {
			return "SAF_03: Fragmento invalido"
		}
		partIdx, err1 := strconv.Atoi(strings.TrimSpace(parts[1]))
		partTotal, err2 := strconv.Atoi(strings.TrimSpace(parts[2]))
		if err1 != nil || err2 != nil || partIdx < 1 || partIdx > partTotal {
			return "SAF_03: Fragmento invalido"
		}
		chunk, err := decodeAutoFirmaB64(parts[3])
		if err != nil {
			return "SAF_03: Fragmento invalido"
		}
		s.serviceMux.Lock()
		next, upErr := upsertLegacyFragment(s.serviceFragments, partIdx, string(chunk))
		if upErr != nil {
			s.serviceMux.Unlock()
			return "SAF_03: Fragmento invalido"
		}
		if totalLegacyFragmentsSize(next) > legacyMaxServicePayloadBytes {
			s.serviceFragments = nil
			s.serviceResponseParts = nil
			s.serviceMux.Unlock()
			return legacyMemoryError
		}
		s.serviceFragments = next
		s.serviceMux.Unlock()
		if partIdx == partTotal {
			return "OK"
		}
		return "MORE_DATA_NEED"
	}

	if _, ok := extractLegacyParam(req, "firm="); ok {
		s.serviceMux.Lock()
		alreadyPrepared := len(s.serviceResponseParts) > 0
		totalPrepared := len(s.serviceResponseParts)
		s.serviceMux.Unlock()
		if alreadyPrepared {
			return strconv.Itoa(totalPrepared)
		}

		s.serviceMux.Lock()
		joined := strings.Join(s.serviceFragments, "")
		s.serviceMux.Unlock()
		if strings.TrimSpace(joined) == "" {
			return "SAF_03: No hay datos fragmentados"
		}
		joined = ensureProtocolVersionParam(joined, s.getServiceProtocolVersion())
		result := s.processProtocolRequest(joined)
		joinedLower := strings.ToLower(joined)
		if strings.HasPrefix(joinedLower, "afirma://save?") || strings.HasPrefix(joinedLower, "afirma://save/?") {
			if result == "SAVE_OK" || result == "OK" {
				return "SAVE_OK"
			}
			if result == "CANCEL" {
				return "CANCEL"
			}
			return "SAF_03: Parametros incorrectos"
		}
		s.serviceMux.Lock()
		s.serviceResponseParts = splitLegacyResponse(result)
		total := len(s.serviceResponseParts)
		s.serviceMux.Unlock()
		if total <= 0 {
			return "0"
		}
		return strconv.Itoa(total)
	}

	if v, ok := extractLegacyParam(req, "send="); ok {
		parts := strings.Split(v, "@")
		if len(parts) < 3 {
			return "SAF_03: Peticion send invalida"
		}
		partIdx, err1 := strconv.Atoi(strings.TrimSpace(parts[1]))
		partTotal, err2 := strconv.Atoi(strings.TrimSpace(parts[2]))
		if err1 != nil || err2 != nil || partIdx < 1 || partIdx > partTotal {
			return "SAF_03: Peticion send invalida"
		}
		s.serviceMux.Lock()
		defer s.serviceMux.Unlock()
		if partIdx > len(s.serviceResponseParts) {
			return "SAF_03: Peticion send invalida"
		}
		return s.serviceResponseParts[partIdx-1]
	}

	return "SAF_03: Parametros incorrectos"
}

func (s *WebSocketServer) checkLegacySessionID(raw string) error {
	return s.checkLegacySessionIDValue(extractLegacySessionID(raw))
}

func (s *WebSocketServer) checkLegacySessionIDValue(got string) error {
	expected := strings.TrimSpace(s.session)
	if expected == "" {
		return nil
	}
	if got == "" {
		return fmt.Errorf("faltante")
	}
	if got != expected {
		return fmt.Errorf("mismatch")
	}
	return nil
}

func extractLegacySessionID(raw string) string {
	idx := strings.Index(strings.ToLower(raw), "idsession=")
	if idx < 0 {
		return ""
	}
	start := idx + len("idsession=")
	end := len(raw)
	lowerTail := strings.ToLower(raw[start:])
	for _, sep := range []string{"@eof", "&", " http/", "\r", "\n"} {
		if i := strings.Index(lowerTail, sep); i >= 0 {
			if start+i < end {
				end = start + i
			}
		}
	}
	return strings.TrimSpace(raw[start:end])
}

func trimBuilderTail(b *strings.Builder, n int) {
	if n <= 0 {
		return
	}
	s := b.String()
	if n >= len(s) {
		b.Reset()
		return
	}
	b.Reset()
	b.WriteString(s[:len(s)-n])
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func splitLegacyResponse(resp string) []string {
	if resp == "" {
		return nil
	}
	parts := make([]string, 0, (len(resp)/legacyResponseMaxSize)+1)
	for i := 0; i < len(resp); i += legacyResponseMaxSize {
		end := i + legacyResponseMaxSize
		if end > len(resp) {
			end = len(resp)
		}
		parts = append(parts, resp[i:end])
	}
	return parts
}

func hasLegacyEOF(s string) bool {
	return indexLegacyEOF(s) >= 0
}

func indexLegacyEOF(s string) int {
	return strings.Index(strings.ToLower(s), strings.ToLower(legacyEOFMarker))
}

func (s *WebSocketServer) resetLegacyServiceState() {
	s.serviceMux.Lock()
	s.serviceFragments = nil
	s.serviceResponseParts = nil
	s.serviceMux.Unlock()
}

func extractLegacyParam(raw, key string) (string, bool) {
	lowerRaw := strings.ToLower(raw)
	lowerKey := strings.ToLower(key)
	idx := strings.Index(lowerRaw, lowerKey)
	if idx < 0 {
		return "", false
	}
	start := idx + len(key)
	end := len(raw)
	lowerTail := strings.ToLower(raw[start:])
	for _, sep := range []string{"idsession=", "@eof", "&", " http/", "\r", "\n"} {
		if i := strings.Index(lowerTail, sep); i >= 0 {
			if start+i < end {
				end = start + i
			}
		}
	}
	val := strings.TrimSpace(raw[start:end])
	val = strings.TrimPrefix(val, "?")
	if decoded, err := url.QueryUnescape(val); err == nil {
		val = decoded
	}
	return val, true
}

func extractLegacyPayload(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if idx := strings.Index(raw, "\r\n\r\n"); idx >= 0 && idx+4 <= len(raw) {
		return raw[idx+4:]
	}
	if idx := strings.Index(raw, "\n\n"); idx >= 0 && idx+2 <= len(raw) {
		return raw[idx+2:]
	}
	return raw
}

func totalLegacyFragmentsSize(frags []string) int {
	total := 0
	for _, f := range frags {
		total += len(f)
	}
	return total
}

func normalizeLegacyRequestPayload(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || hasAnyLegacyCommand(raw) {
		return raw
	}
	candidate := raw
	for i := 0; i < 2; i++ {
		decoded, err := url.QueryUnescape(candidate)
		if err != nil {
			return raw
		}
		decoded = strings.TrimSpace(decoded)
		if decoded == "" || decoded == candidate {
			break
		}
		if hasAnyLegacyCommand(decoded) {
			return decoded
		}
		candidate = decoded
	}
	return raw
}

func hasAnyLegacyCommand(raw string) bool {
	lower := strings.ToLower(raw)
	return strings.Contains(lower, "cmd=") ||
		strings.Contains(lower, "echo=") ||
		strings.Contains(lower, "fragment=") ||
		strings.Contains(lower, "firm=") ||
		strings.Contains(lower, "send=")
}

func upsertLegacyFragment(frags []string, partIdx int, chunk string) ([]string, error) {
	if partIdx <= 0 {
		return nil, fmt.Errorf("invalid part")
	}
	if len(frags) == partIdx {
		// Java parity: when size == part, replace existing part.
		frags[partIdx-1] = chunk
		return frags, nil
	}
	insertPos := partIdx - 1
	if insertPos < 0 || insertPos > len(frags) {
		// Java ArrayList.add(index, ...) rejects gaps/out-of-order inserts.
		return nil, fmt.Errorf("out of order")
	}
	frags = append(frags, "")
	copy(frags[insertPos+1:], frags[insertPos:])
	frags[insertPos] = chunk
	return frags, nil
}

func ensureProtocolVersionParam(uri string, v int) string {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return uri
	}
	u, err := url.Parse(uri)
	if err != nil {
		return uri
	}
	if !strings.EqualFold(u.Scheme, "afirma") {
		return uri
	}
	action := normalizeProtocolAction(extractProtocolAction(u))
	if action == "" {
		action = normalizeProtocolAction(getQueryParam(u.Query(), "op", "operation", "action"))
	}
	if action == "websocket" || action == "service" {
		return uri
	}
	if strings.TrimSpace(getQueryParam(u.Query(), "v")) != "" {
		return uri
	}
	q := u.Query()
	q.Set("v", strconv.Itoa(v))
	u.RawQuery = q.Encode()
	return u.String()
}
