// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"errors"
	"encoding/base64"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestLegacyServiceSessionValidation(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "abc", nil)
	if got := s.processLegacyServicePayload("echo=-@EOFidsession=zzz"); !strings.HasPrefix(got, "SAF_03:") {
		t.Fatalf("se esperaba SAF_03 por idsession invalido en service legacy (paridad Java), obtenido: %q", got)
	}
	if got := s.processLegacyServicePayload("echo=-@EOFidsession=abc"); got != "OK" {
		t.Fatalf("se esperaba OK con idsession valido, obtenido: %q", got)
	}
	if got := s.processLegacyServicePayload("echo=-@EOFidSession=abc"); got != "OK" {
		t.Fatalf("se esperaba OK con idSession valido, obtenido: %q", got)
	}
}

func TestLegacyServiceCmdFlow(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	cmdURI := "afirma://websocket?idsession=abc&ports=63117"
	cmdB64 := base64.StdEncoding.EncodeToString([]byte(cmdURI))
	got := s.processLegacyServicePayload("GET /?cmd=" + cmdB64 + " HTTP/1.1")
	if got != "1" {
		t.Fatalf("se esperaba total de partes=1 en cmd flow, obtenido: %q", got)
	}
	if got := s.processLegacyServicePayload("send=@1@1idsession=abc@EOF"); got != "OK" {
		t.Fatalf("se esperaba OK en parte unica de cmd flow, obtenido: %q", got)
	}
}

func TestLegacyServiceCmdFlowUppercaseScheme(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	cmdURI := "AFIRMA://WEBSOCKET?idsession=abc&ports=63117"
	cmdB64 := base64.StdEncoding.EncodeToString([]byte(cmdURI))
	got := s.processLegacyServicePayload("GET /?cmd=" + cmdB64 + " HTTP/1.1")
	if got != "1" {
		t.Fatalf("se esperaba total de partes=1 en cmd flow uppercase, obtenido: %q", got)
	}
	if got := s.processLegacyServicePayload("send=@1@1idsession=abc@EOF"); got != "OK" {
		t.Fatalf("se esperaba OK en parte unica de cmd flow uppercase, obtenido: %q", got)
	}
}

func TestLegacyServiceCmdUppercaseCommandName(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	cmdURI := "afirma://websocket?idsession=abc&ports=63117"
	cmdB64 := base64.StdEncoding.EncodeToString([]byte(cmdURI))
	got := s.processLegacyServicePayload("CMD=" + cmdB64 + "idsession=abc@EOF")
	if got != "1" {
		t.Fatalf("CMD= en mayusculas debe procesarse igual que cmd=, obtenido: %q", got)
	}
}

func TestLegacyServiceEchoUppercaseResetsState(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	s.serviceFragments = []string{"a", "b"}
	s.serviceResponseParts = []string{"p1"}

	got := s.processLegacyServicePayload("ECHO=-idsession=abc@EOF")
	if got != "OK" {
		t.Fatalf("ECHO= en mayusculas debe devolver OK, obtenido: %q", got)
	}
	if len(s.serviceFragments) != 0 || len(s.serviceResponseParts) != 0 {
		t.Fatalf("ECHO=- debe resetear estado legacy")
	}
}

func TestLegacyServiceCmdFlowCamelCaseSessionSuffix(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	cmdURI := "afirma://websocket?idsession=abc&ports=63117"
	cmdB64 := base64.StdEncoding.EncodeToString([]byte(cmdURI))
	got := s.processLegacyServicePayload("GET /?cmd=" + cmdB64 + "idSession=abc@EOF HTTP/1.1")
	if got != "1" {
		t.Fatalf("se esperaba total de partes=1 en cmd flow con idSession, obtenido: %q", got)
	}
	if got := s.processLegacyServicePayload("send=@1@1idSession=abc@EOF"); got != "OK" {
		t.Fatalf("se esperaba OK en parte unica de cmd flow con idSession, obtenido: %q", got)
	}
}

func TestLegacyServiceCmdSaveErrorMapsToSaf03(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	cmdURI := "afirma://save?id=1"
	cmdB64 := base64.StdEncoding.EncodeToString([]byte(cmdURI))
	got := s.processLegacyServicePayload("GET /?cmd=" + cmdB64 + " HTTP/1.1")
	if !strings.HasPrefix(got, "SAF_03:") {
		t.Fatalf("save en cmd con error debe mapear a SAF_03, obtenido: %q", got)
	}
}

func TestLegacyServiceFragmentFirmSendFlow(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	uri := "afirma://websocket?idsession=abc&ports=63117"
	chunk := base64.StdEncoding.EncodeToString([]byte(uri))

	if got := s.processLegacyServicePayload("fragment=@1@1@" + chunk + "idsession=abc@EOF"); got != "OK" {
		t.Fatalf("fragment final debe devolver OK, obtenido: %q", got)
	}
	parts := s.processLegacyServicePayload("firm=idsession=abc@EOF")
	if parts != "1" {
		t.Fatalf("firm debe devolver numero de partes=1, obtenido: %q", parts)
	}
	if got := s.processLegacyServicePayload("send=@1@1idsession=abc@EOF"); got != "OK" {
		t.Fatalf("send de la parte 1 debe devolver OK, obtenido: %q", got)
	}
}

func TestLegacyServiceUnsupportedCommandReturnsSaf03(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	got := s.processLegacyServicePayload("foo=baridsession=abc@EOF")
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_03:") {
		t.Fatalf("comando legacy no soportado debe mapear a SAF_03, obtenido: %q", got)
	}
}

func TestLegacyServiceCommandPriorityCmdOverEcho(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	cmdURI := "afirma://websocket?idsession=abc&ports=63117"
	cmdB64 := base64.StdEncoding.EncodeToString([]byte(cmdURI))
	raw := "echo=-idsession=abc@EOFcmd=" + cmdB64 + "idsession=abc@EOF"
	got := s.processLegacyServicePayload(raw)
	if got != "1" {
		t.Fatalf("prioridad cmd sobre echo esperada (Java), obtenido: %q", got)
	}
}

func TestLegacyServiceFragmentHTTPBodyFlow(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	uri := "afirma://websocket?idsession=abc&ports=63117"
	chunk := base64.StdEncoding.EncodeToString([]byte(uri))
	req := "POST /afirma HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" +
		"fragment=@1@1@" + chunk + "idsession=abc@EOF"
	if got := s.processLegacyServicePayload(req); got != "OK" {
		t.Fatalf("fragment HTTP body debe devolver OK, obtenido: %q", got)
	}
}

func TestLegacyServiceFragmentAndSendWithCamelCaseSessionSuffix(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	uri := "afirma://websocket?idsession=abc&ports=63117"
	chunk := base64.StdEncoding.EncodeToString([]byte(uri))
	if got := s.processLegacyServicePayload("fragment=@1@1@" + chunk + "idSession=abc@EOF"); got != "OK" {
		t.Fatalf("fragment con idSession debe devolver OK, obtenido: %q", got)
	}
	parts := s.processLegacyServicePayload("firm=idSession=abc@EOF")
	if parts != "1" {
		t.Fatalf("firm con idSession debe devolver numero de partes=1, obtenido: %q", parts)
	}
	if got := s.processLegacyServicePayload("send=@1@1idSession=abc@EOF"); got != "OK" {
		t.Fatalf("send con idSession debe devolver OK, obtenido: %q", got)
	}
}

func TestLegacyServiceUppercaseFragmentFirmSendFlow(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	uri := "afirma://websocket?idsession=abc&ports=63117"
	chunk := base64.StdEncoding.EncodeToString([]byte(uri))

	if got := s.processLegacyServicePayload("FRAGMENT=@1@1@" + chunk + "idsession=abc@EOF"); got != "OK" {
		t.Fatalf("FRAGMENT en mayusculas debe devolver OK, obtenido: %q", got)
	}
	if parts := s.processLegacyServicePayload("FIRM=idsession=abc@EOF"); parts != "1" {
		t.Fatalf("FIRM en mayusculas debe devolver numero de partes=1, obtenido: %q", parts)
	}
	if got := s.processLegacyServicePayload("SEND=@1@1idsession=abc@EOF"); got != "OK" {
		t.Fatalf("SEND en mayusculas debe devolver OK, obtenido: %q", got)
	}
}

func TestLegacyServiceFirmWithoutFragmentsReturnsSaf03(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	got := s.processLegacyServicePayload("firm=idsession=abc@EOF")
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_03:") {
		t.Fatalf("firm sin fragmentos debe devolver SAF_03, obtenido: %q", got)
	}
}

func TestLegacyServiceFirmReturnsPreparedPartsCountOnRetry(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	s.serviceResponseParts = []string{"P1", "P2"}
	got := s.processLegacyServicePayload("firm=idsession=abc@EOF")
	if got != "2" {
		t.Fatalf("firm con respuesta preparada debe devolver numero de partes, obtenido: %q", got)
	}
}

func TestLegacyServiceSendInvalidRangeReturnsSaf03(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	s.serviceResponseParts = []string{"P1"}
	got := s.processLegacyServicePayload("send=@2@1idsession=abc@EOF")
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_03:") {
		t.Fatalf("send fuera de rango debe devolver SAF_03, obtenido: %q", got)
	}
}

func TestLegacyServiceSendAllowsMismatchedTotalWhenPartExists(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	s.serviceResponseParts = []string{"P1"}
	got := s.processLegacyServicePayload("send=@1@999idsession=abc@EOF")
	if got != "P1" {
		t.Fatalf("send debe devolver la parte aunque total no coincida (paridad Java), obtenido: %q", got)
	}
}

func TestLegacyServiceFragmentInvalidReturnsSaf03(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	got := s.processLegacyServicePayload("fragment=@x@1@YQ==idsession=abc@EOF")
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_03:") {
		t.Fatalf("fragment invalido debe devolver SAF_03, obtenido: %q", got)
	}
}

func TestLegacyServiceFragmentOutOfOrderReturnsSaf03(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	chunk := base64.StdEncoding.EncodeToString([]byte("afirma://websocket?idsession=abc&ports=63117"))
	got := s.processLegacyServicePayload("fragment=@2@2@" + chunk + "idsession=abc@EOF")
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_03:") {
		t.Fatalf("fragment fuera de orden debe devolver SAF_03 (paridad Java), obtenido: %q", got)
	}
}

func TestLegacyServiceFragmentTooLargeReturnsMemoryError(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	oldLimit := legacyMaxServicePayloadBytes
	legacyMaxServicePayloadBytes = 16
	defer func() { legacyMaxServicePayloadBytes = oldLimit }()

	largeChunk := strings.Repeat("A", 32)
	chunkB64 := base64.StdEncoding.EncodeToString([]byte(largeChunk))
	got := s.processLegacyServicePayload("fragment=@1@1@" + chunkB64 + "idsession=abc@EOF")
	if got != "MEMORY_ERROR" {
		t.Fatalf("fragmento demasiado grande debe devolver MEMORY_ERROR, obtenido: %q", got)
	}
	if len(s.serviceFragments) != 0 || len(s.serviceResponseParts) != 0 {
		t.Fatalf("tras MEMORY_ERROR debe limpiarse estado legacy")
	}
}

func TestLegacyServiceCmdInvalidBase64ReturnsSaf03(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	got := s.processLegacyServicePayload("cmd=***idsession=abc@EOF")
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_03:") {
		t.Fatalf("cmd base64 invalido debe devolver SAF_03, obtenido: %q", got)
	}
}

func TestLegacyServiceCmdURLEncodedBase64(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	cmdURI := "afirma://websocket?idsession=abc&ports=63117"
	cmdB64 := base64.StdEncoding.EncodeToString([]byte(cmdURI))
	cmdEscaped := url.QueryEscape(cmdB64)
	got := s.processLegacyServicePayload("GET /?cmd=" + cmdEscaped + " HTTP/1.1")
	if got != "1" {
		t.Fatalf("cmd URL-encoded debe procesarse y devolver partes=1, obtenido: %q", got)
	}
}

func TestLegacyServicePayloadFullyURLEncoded(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	cmdURI := "afirma://websocket?idsession=abc&ports=63117"
	cmdB64 := base64.StdEncoding.EncodeToString([]byte(cmdURI))
	encoded := url.QueryEscape("cmd=" + cmdB64 + "idsession=abc@EOF")
	got := s.processLegacyServicePayload(encoded)
	if got != "1" {
		t.Fatalf("payload legacy url-encoded completo debe procesar cmd, obtenido: %q", got)
	}
	if got := s.processLegacyServicePayload("send=@1@1idsession=abc@EOF"); got != "OK" {
		t.Fatalf("send tras cmd url-encoded debe devolver OK, obtenido: %q", got)
	}
}

func TestLegacyServicePayloadDoubleURLEncoded(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	cmdURI := "afirma://websocket?idsession=abc&ports=63117"
	cmdB64 := base64.StdEncoding.EncodeToString([]byte(cmdURI))
	once := url.QueryEscape("cmd=" + cmdB64 + "idsession=abc@EOF")
	twice := url.QueryEscape(once)
	got := s.processLegacyServicePayload(twice)
	if got != "1" {
		t.Fatalf("payload legacy doble url-encoded debe procesar cmd, obtenido: %q", got)
	}
}

func TestLegacyServiceCmdInheritsServiceProtocolVersion(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	// Valor fuera de rango para observar claramente la herencia en cmd sin v.
	s.setServiceProtocolVersion(5)

	cmdURI := "afirma://sign?id=abc&stservlet=https%3A%2F%2Fexample.com%2FStorageService"
	cmdB64 := base64.StdEncoding.EncodeToString([]byte(cmdURI))
	got := s.processLegacyServicePayload("GET /?cmd=" + cmdB64 + " HTTP/1.1")
	if got != "1" {
		t.Fatalf("cmd debe preparar una respuesta en una parte, obtenido: %q", got)
	}
	part := s.processLegacyServicePayload("send=@1@1idsession=abc@EOF")
	if !strings.HasPrefix(strings.ToUpper(part), "SAF_21:") {
		t.Fatalf("cmd legacy debe heredar v del canal service (esperado SAF_21), obtenido: %q", part)
	}
}

func TestLegacyServiceCmdNonAfirmaURIReturnsSaf03(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	cmdB64 := base64.StdEncoding.EncodeToString([]byte("https://example.com"))
	got := s.processLegacyServicePayload("cmd=" + cmdB64 + "idsession=abc@EOF")
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_03:") {
		t.Fatalf("cmd no afirma:// debe devolver SAF_03, obtenido: %q", got)
	}
}

func TestLegacyServiceCmdServiceURIReturnsSaf03(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	cmdB64 := base64.StdEncoding.EncodeToString([]byte("afirma://service?ports=1"))
	got := s.processLegacyServicePayload("cmd=" + cmdB64 + "idsession=abc@EOF")
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_03:") {
		t.Fatalf("cmd afirma://service debe devolver SAF_03, obtenido: %q", got)
	}
}

func TestExtractLegacySessionID(t *testing.T) {
	if got := extractLegacySessionID("...idsession=abc@EOF..."); got != "abc" {
		t.Fatalf("idsession inesperado: %q", got)
	}
	if got := extractLegacySessionID("...idSession=def@EOF..."); got != "def" {
		t.Fatalf("idSession inesperado: %q", got)
	}
	if got := extractLegacySessionID("...idsession=abc&x=1..."); got != "abc" {
		t.Fatalf("idsession inesperado con &: %q", got)
	}
	if got := extractLegacySessionID("sin_idsession"); got != "" {
		t.Fatalf("idsession esperado vacio, obtenido: %q", got)
	}
}

func TestReadLegacySocketPayloadExtractsSessionAndTrimsEOF(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		_, _ = client.Write([]byte("POST /afirma HTTP/1.1\r\nHost: localhost\r\n\r\nfragment=@1@1@YQ==idsession=abc@EOF"))
		_ = client.Close()
	}()

	res, err := readLegacySocketPayload(server)
	if err != nil {
		t.Fatalf("readLegacySocketPayload error: %v", err)
	}
	if res.SessionID != "abc" {
		t.Fatalf("idsession inesperado: %q", res.SessionID)
	}
	if !strings.Contains(res.RequestBody, "fragment=@1@1@YQ==") {
		t.Fatalf("payload inesperado: %q", res.RequestBody)
	}
	if strings.Contains(res.RequestBody, "idsession=") || strings.Contains(res.RequestBody, "@EOF") {
		t.Fatalf("payload debe venir sin idsession/@EOF: %q", res.RequestBody)
	}
}

func TestReadLegacySocketPayloadExtractsCamelCaseSession(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		_, _ = client.Write([]byte("POST /afirma HTTP/1.1\r\nHost: localhost\r\n\r\nfragment=@1@1@YQ==idSession=abc@EOF"))
		_ = client.Close()
	}()

	res, err := readLegacySocketPayload(server)
	if err != nil {
		t.Fatalf("readLegacySocketPayload error: %v", err)
	}
	if res.SessionID != "abc" {
		t.Fatalf("idSession inesperado: %q", res.SessionID)
	}
}

func TestReadLegacySocketPayloadSplitEOFAcrossChunks(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		_, _ = client.Write([]byte("echo=-idsession=abc@E"))
		_, _ = client.Write([]byte("OF"))
		_ = client.Close()
	}()

	res, err := readLegacySocketPayload(server)
	if err != nil {
		t.Fatalf("readLegacySocketPayload error: %v", err)
	}
	if res.SessionID != "abc" {
		t.Fatalf("idsession inesperado en EOF fragmentado: %q", res.SessionID)
	}
	if strings.Contains(res.RequestBody, "@EOF") {
		t.Fatalf("payload no debe incluir @EOF: %q", res.RequestBody)
	}
}

func TestReadLegacySocketPayloadLowercaseEOF(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		_, _ = client.Write([]byte("echo=-idsession=abc@eof"))
		_ = client.Close()
	}()

	res, err := readLegacySocketPayload(server)
	if err != nil {
		t.Fatalf("readLegacySocketPayload error: %v", err)
	}
	if res.SessionID != "abc" {
		t.Fatalf("idsession inesperado con @eof: %q", res.SessionID)
	}
	if strings.Contains(strings.ToLower(res.RequestBody), "@eof") {
		t.Fatalf("payload no debe incluir @eof: %q", res.RequestBody)
	}
}

func TestLegacyServiceFragmentURLEncodedChunk(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	uri := "afirma://websocket?idsession=abc&ports=63117"
	chunk := base64.StdEncoding.EncodeToString([]byte(uri))
	chunkEscaped := url.QueryEscape(chunk)

	if got := s.processLegacyServicePayload("fragment=@1@1@" + chunkEscaped + "idsession=abc@EOF"); got != "OK" {
		t.Fatalf("fragment URL-encoded debe devolver OK, obtenido: %q", got)
	}
	if parts := s.processLegacyServicePayload("firm=idsession=abc@EOF"); parts != "1" {
		t.Fatalf("firm tras fragment URL-encoded debe devolver partes=1, obtenido: %q", parts)
	}
}

func TestReadLegacySocketPayloadTooLargeReturnsError(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	oldMax := legacyMaxRawRequestBytes
	legacyMaxRawRequestBytes = 64
	defer func() { legacyMaxRawRequestBytes = oldMax }()

	go func() {
		payload := "fragment=@1@1@" + strings.Repeat("A", 256) + "idsession=abc@EOF"
		_, _ = client.Write([]byte(payload))
		_ = client.Close()
	}()

	_, err := readLegacySocketPayload(server)
	if err != errLegacyRequestTooLarge {
		t.Fatalf("se esperaba errLegacyRequestTooLarge, obtenido: %v", err)
	}
}

type legacyReadErrorConn struct {
	writes strings.Builder
}

func (c *legacyReadErrorConn) Read(_ []byte) (int, error) {
	return 0, errors.New("forced read error")
}

func (c *legacyReadErrorConn) Write(b []byte) (int, error) {
	c.writes.Write(b)
	return len(b), nil
}

func (c *legacyReadErrorConn) Close() error { return nil }

func (c *legacyReadErrorConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 63117}
}

func (c *legacyReadErrorConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 51234}
}

func (c *legacyReadErrorConn) SetDeadline(_ time.Time) error      { return nil }
func (c *legacyReadErrorConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *legacyReadErrorConn) SetWriteDeadline(_ time.Time) error { return nil }

type legacyPayloadConn struct {
	payload []byte
	offset  int
	writes  strings.Builder
}

func (c *legacyPayloadConn) Read(p []byte) (int, error) {
	if c.offset >= len(c.payload) {
		return 0, io.EOF
	}
	n := copy(p, c.payload[c.offset:])
	c.offset += n
	return n, nil
}

func (c *legacyPayloadConn) Write(b []byte) (int, error) {
	c.writes.Write(b)
	return len(b), nil
}

func (c *legacyPayloadConn) Close() error { return nil }

func (c *legacyPayloadConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 63117}
}

func (c *legacyPayloadConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 51234}
}

func (c *legacyPayloadConn) SetDeadline(_ time.Time) error      { return nil }
func (c *legacyPayloadConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *legacyPayloadConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestHandleLegacyServiceConnReadErrorReturnsSaf03(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	conn := &legacyReadErrorConn{}

	s.handleLegacyServiceConn(conn)

	want := base64.RawURLEncoding.EncodeToString([]byte("SAF_03: Parametros incorrectos"))
	if !strings.Contains(conn.writes.String(), want) {
		t.Fatalf("ante error de lectura debe responder SAF_03, obtenido: %q", conn.writes.String())
	}
}

func TestHandleLegacyServiceConnTooLargeReturnsMemoryError(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)

	oldMax := legacyMaxRawRequestBytes
	legacyMaxRawRequestBytes = 64
	defer func() { legacyMaxRawRequestBytes = oldMax }()

	payload := "fragment=@1@1@" + strings.Repeat("A", 256) + "idsession=abc@EOF"
	conn := &legacyPayloadConn{payload: []byte(payload)}

	s.handleLegacyServiceConn(conn)

	want := base64.RawURLEncoding.EncodeToString([]byte(legacyMemoryError))
	if !strings.Contains(conn.writes.String(), want) {
		t.Fatalf("ante request cruda demasiado grande debe responder MEMORY_ERROR, obtenido: %q", conn.writes.String())
	}
}
