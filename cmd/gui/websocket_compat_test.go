// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"autofirma-host/pkg/certstore"
	"autofirma-host/pkg/protocol"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFormatErrorReturnsJavaStyleSAF(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)

	cases := []struct {
		in   string
		want string
	}{
		{"ERROR_INVALID_PROTOCOL", "SAF_02:"},
		{"ERROR_PARSING_URI", "SAF_03:"},
		{"ERROR_DOWNLOAD", "SAF_16:"},
		{"ERROR_PARSING_XML", "SAF_03:"},
		{"ERROR_SAVING_DATA", "SAF_05:"},
		{"ERROR_BUILD_RESP", "SAF_12:"},
		{"ERROR_SIGNATURE_FAILED", "SAF_09:"},
		{"ERROR_CANNOT_ACCESS_KEYSTORE", "SAF_08:"},
		{"ERROR_NO_CERTIFICATES_SYSTEM", "SAF_10:"},
		{"ERROR_NO_CERTIFICATES_KEYSTORE", "SAF_19:"},
		{"ERROR_LOCAL_BATCH_SIGN", "SAF_20:"},
		{"ERROR_UNSUPPORTED_PROCEDURE", "SAF_21:"},
		{"ERROR_CONTACT_BATCH_SERVICE", "SAF_26:"},
		{"ERROR_BATCH_SIGNATURE", "SAF_27:"},
		{"ERROR_MINIMUM_VERSION_NOT_SATISFIED", "SAF_41:"},
		{"ERROR_CANNOT_OPEN_SOCKET", "SAF_45:"},
		{"ERROR_INVALID_SESSION_ID", "SAF_46:"},
		{"ERROR_EXTERNAL_REQUEST_TO_SOCKET", "SAF_47:"},
		{"OTRO", "SAF_03:"},
	}

	for _, tc := range cases {
		got := s.formatError(tc.in, "detalle")
		if !strings.HasPrefix(got, tc.want) {
			t.Fatalf("codigo %s -> %q (esperado prefijo %q)", tc.in, got, tc.want)
		}
	}
}

func TestProcessProtocolRequestBatchReturnsSaf04(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	got := strings.TrimSpace(s.processProtocolRequest("afirma://batch?id=abc&dat=abc123"))
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_04:") {
		t.Fatalf("se esperaba SAF_04 para batch no JSON/trifasico no soportado, obtenido: %q", got)
	}
}

func TestProcessProtocolRequestInvalidProtocolReturnsSaf02CanonicalMessage(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	got := strings.TrimSpace(s.processProtocolRequest("http://example.com"))
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_02:") {
		t.Fatalf("se esperaba SAF_02 para protocolo invalido, obtenido: %q", got)
	}
	if !strings.Contains(strings.ToLower(got), "protocolo no soportado") {
		t.Fatalf("mensaje canonico inesperado para SAF_02: %q", got)
	}
}

func TestProcessProtocolRequestUppercaseSchemeAccepted(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	got := strings.TrimSpace(s.processProtocolRequest("AFIRMA://sign?id=abc&stservlet=https%3A%2F%2Fexample.com%2FStorageService"))
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_09:") {
		t.Fatalf("se esperaba flujo valido (SAF_09 por falta UI) con esquema en mayusculas, obtenido: %q", got)
	}
}

func TestProcessProtocolRequestNeedsUIForSign(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	got := strings.TrimSpace(s.processProtocolRequest("afirma://sign?id=abc&stservlet=https%3A%2F%2Fexample.com%2FStorageService"))
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_09:") {
		t.Fatalf("se esperaba SAF_09 por UI no disponible, obtenido: %q", got)
	}
}

func TestProcessProtocolRequestMinimumClientVersionNotSatisfiedReturnsSaf41(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	got := strings.TrimSpace(s.processProtocolRequest("afirma://sign?id=abc&stservlet=https%3A%2F%2Fexample.com%2FStorageService&mcv=9.0"))
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_41:") {
		t.Fatalf("se esperaba SAF_41 para mcv no satisfecha, obtenido: %q", got)
	}
}

func TestProcessProtocolRequestUnsupportedProcedureVersionReturnsSaf21(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	got := strings.TrimSpace(s.processProtocolRequest("afirma://sign?id=abc&stservlet=https%3A%2F%2Fexample.com%2FStorageService&v=5"))
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_21:") {
		t.Fatalf("se esperaba SAF_21 para version de protocolo no soportada, obtenido: %q", got)
	}
}

func TestBuildProtocolExtraInfo(t *testing.T) {
	if got := buildProtocolExtraInfo(&ProtocolState{ProtocolVersion: 2}, "/tmp/a.pdf"); got != nil {
		t.Fatalf("v<3 no debe devolver extraInfo")
	}
	got := buildProtocolExtraInfo(&ProtocolState{ProtocolVersion: 3}, "/tmp/a.pdf")
	if len(got) == 0 {
		t.Fatalf("v>=3 debe devolver extraInfo")
	}
	var data map[string]string
	if err := json.Unmarshal(got, &data); err != nil {
		t.Fatalf("extraInfo no es JSON valido: %v", err)
	}
	if data["filename"] != "a.pdf" {
		t.Fatalf("filename inesperado en extraInfo: %q", data["filename"])
	}
}

func TestBuildResponseIncludesExtraInfoWhenPresent(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	certDER := []byte{0x30, 0x82, 0x01}
	sig := []byte("firma")
	extra := []byte(`{"filename":"doc.pdf"}`)
	out, err := s.buildResponse(certDER, sig, "", extra)
	if err != nil {
		t.Fatalf("error inesperado construyendo respuesta: %v", err)
	}
	parts := strings.Split(out, "|")
	if len(parts) != 3 {
		t.Fatalf("se esperaban 3 partes cert|sign|extra, obtenido=%d (%q)", len(parts), out)
	}
	decodedExtra, err := base64.URLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("extraInfo no es base64 url-safe valido: %v", err)
	}
	if string(decodedExtra) != string(extra) {
		t.Fatalf("extraInfo inesperado: %q", string(decodedExtra))
	}
}

func TestBuildResponseEncryptedIncludesExtraInfoWhenPresent(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	certDER := []byte{0x30, 0x82, 0x01}
	sig := []byte("firma")
	extra := []byte(`{"filename":"doc.pdf"}`)
	out, err := s.buildResponse(certDER, sig, "12345678", extra)
	if err != nil {
		t.Fatalf("error inesperado construyendo respuesta cifrada: %v", err)
	}
	parts := strings.Split(out, "|")
	if len(parts) != 3 {
		t.Fatalf("en cifrado se esperaban 3 partes cert|sign|extra, obtenido=%d (%q)", len(parts), out)
	}
}

func TestProcessProtocolRequestCosignUsesSignFlowAndNeedsUI(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	got := strings.TrimSpace(s.processProtocolRequest("afirma://cosign?id=abc&stservlet=https%3A%2F%2Fexample.com%2FStorageService"))
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_09:") {
		t.Fatalf("se esperaba SAF_09 para cosign sin UI, obtenido: %q", got)
	}
}

func TestProcessProtocolRequestSpanishActionAliasesNeedUI(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	uris := []string{
		"afirma://firmar?id=abc&stservlet=https%3A%2F%2Fexample.com%2FStorageService",
		"afirma://cofirmar?id=abc&stservlet=https%3A%2F%2Fexample.com%2FStorageService",
		"afirma://contrafirmar?id=abc&stservlet=https%3A%2F%2Fexample.com%2FStorageService",
	}
	for _, uri := range uris {
		got := strings.TrimSpace(s.processProtocolRequest(uri))
		if !strings.HasPrefix(strings.ToUpper(got), "SAF_09:") {
			t.Fatalf("se esperaba SAF_09 para alias %q sin UI, obtenido: %q", uri, got)
		}
	}
}

func TestProcessProtocolRequestUnsupportedOperationsReturnSaf04(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	ops := []string{
		"afirma://signbatch?id=1",
	}
	for _, uri := range ops {
		got := strings.TrimSpace(s.processProtocolRequest(uri))
		if !strings.HasPrefix(strings.ToUpper(got), "SAF_04:") {
			t.Fatalf("se esperaba SAF_04 para %q, obtenido: %q", uri, got)
		}
	}
}

func TestProcessProtocolRequestSignAndSaveWithoutDataReturnsSaf44(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	got := strings.TrimSpace(s.processProtocolRequest("afirma://signandsave?id=1"))
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_44:") {
		t.Fatalf("se esperaba SAF_44 para signandsave sin dat, obtenido: %q", got)
	}
}

func TestProcessProtocolRequestSaveWithoutDataReturnsSaf05(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	got := strings.TrimSpace(s.processProtocolRequest("afirma://save?id=1"))
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_05:") {
		t.Fatalf("se esperaba SAF_05 para save sin dat, obtenido: %q", got)
	}
}

func TestProcessSaveRequestCancelReturnsCancel(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", &UI{})
	state := &ProtocolState{
		Action: "save",
		Params: url.Values{
			"dat":      []string{base64.StdEncoding.EncodeToString([]byte("contenido"))},
			"filename": []string{"salida_test"},
			"exts":     []string{"txt"},
		},
	}

	oldSaveDialog := saveDialogFunc
	saveDialogFunc = func(defaultPath string, exts string) (string, bool, error) {
		return "", true, nil
	}
	defer func() { saveDialogFunc = oldSaveDialog }()

	got := s.processSaveRequest(state)
	if got != "CANCEL" {
		t.Fatalf("se esperaba CANCEL al cancelar guardado, obtenido: %q", got)
	}
}

func TestBuildSelectCertResponsePlain(t *testing.T) {
	cert := []byte{0x30, 0x82, 0x01, 0x0A, 0xDE, 0xAD, 0xBE, 0xEF}
	got, err := buildSelectCertResponse(cert, "")
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	want := base64.URLEncoding.EncodeToString(cert)
	if got != want {
		t.Fatalf("respuesta distinta, got=%q want=%q", got, want)
	}
}

func TestBuildSelectCertResponseEncrypted(t *testing.T) {
	cert := []byte("CERTDER")
	got, err := buildSelectCertResponse(cert, "12345678")
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if !strings.Contains(got, ".") {
		t.Fatalf("se esperaba formato AutoFirma cifrado 'pad.base64', obtenido: %q", got)
	}
}

func TestDecodeAutoFirmaB64(t *testing.T) {
	raw := []byte("hola mundo")
	cases := []string{
		base64.StdEncoding.EncodeToString(raw),
		base64.URLEncoding.EncodeToString(raw),
		base64.RawStdEncoding.EncodeToString(raw),
		base64.RawURLEncoding.EncodeToString(raw),
	}
	for _, c := range cases {
		out, err := decodeAutoFirmaB64(c)
		if err != nil {
			t.Fatalf("error inesperado con %q: %v", c, err)
		}
		if string(out) != string(raw) {
			t.Fatalf("decode distinto, got=%q want=%q", string(out), string(raw))
		}
	}
}

func TestBuildSaveTargetPath(t *testing.T) {
	p, err := buildSaveTargetPath("documento", "pdf")
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if !strings.HasSuffix(p, filepath.Join("Descargas", "documento.pdf")) {
		t.Fatalf("ruta inesperada: %q", p)
	}
}

func TestProcessSaveRequestReturnsSaveOK(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	s := NewWebSocketServer([]int{63117}, "", nil)
	state := &ProtocolState{
		Action: "save",
		Params: url.Values{
			"dat":      []string{base64.StdEncoding.EncodeToString([]byte("contenido"))},
			"filename": []string{"salida_test"},
			"exts":     []string{"txt"},
		},
	}

	got := s.processSaveRequest(state)
	if got != "SAVE_OK" {
		t.Fatalf("se esperaba SAVE_OK, obtenido: %q", got)
	}

	saved := filepath.Join(tmpHome, "Descargas", "salida_test.txt")
	b, err := os.ReadFile(saved)
	if err != nil {
		t.Fatalf("no se pudo leer fichero guardado: %v", err)
	}
	if string(b) != "contenido" {
		t.Fatalf("contenido inesperado: %q", string(b))
	}
}

func TestProcessSaveRequestAliasParamsReturnsSaveOK(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	s := NewWebSocketServer([]int{63117}, "", nil)
	state := &ProtocolState{
		Action: "save",
		Params: url.Values{
			"data":      []string{base64.StdEncoding.EncodeToString([]byte("contenido_alias"))},
			"fileName":  []string{"salida_alias"},
			"extensions": []string{"txt"},
		},
	}

	got := s.processSaveRequest(state)
	if got != "SAVE_OK" {
		t.Fatalf("se esperaba SAVE_OK con aliases, obtenido: %q", got)
	}

	saved := filepath.Join(tmpHome, "Descargas", "salida_alias.txt")
	b, err := os.ReadFile(saved)
	if err != nil {
		t.Fatalf("no se pudo leer fichero guardado: %v", err)
	}
	if string(b) != "contenido_alias" {
		t.Fatalf("contenido inesperado: %q", string(b))
	}
}

func TestSplitLoadPaths(t *testing.T) {
	got := splitLoadPaths(" /tmp/a.pdf | /tmp/b.pdf ")
	if len(got) != 2 || got[0] != "/tmp/a.pdf" || got[1] != "/tmp/b.pdf" {
		t.Fatalf("split inesperado: %#v", got)
	}
}

func TestProcessLoadRequestSingle(t *testing.T) {
	tmp := t.TempDir()
	in := filepath.Join(tmp, "entrada.txt")
	if err := os.WriteFile(in, []byte("hola"), 0o644); err != nil {
		t.Fatalf("no se pudo preparar fichero: %v", err)
	}

	s := NewWebSocketServer([]int{63117}, "", nil)
	state := &ProtocolState{
		Action: "load",
		Params: url.Values{
			"filePath": []string{in},
		},
	}
	got := s.processLoadRequest(state)
	if strings.HasPrefix(strings.ToUpper(got), "SAF_") {
		t.Fatalf("resultado de carga inesperado: %q", got)
	}
	if !strings.HasPrefix(got, "entrada.txt:") {
		t.Fatalf("formato inesperado: %q", got)
	}
}

func TestProcessLoadRequestAliasFileParam(t *testing.T) {
	tmp := t.TempDir()
	in := filepath.Join(tmp, "entrada_alias.txt")
	if err := os.WriteFile(in, []byte("hola_alias"), 0o644); err != nil {
		t.Fatalf("no se pudo preparar fichero: %v", err)
	}

	s := NewWebSocketServer([]int{63117}, "", nil)
	state := &ProtocolState{
		Action: "load",
		Params: url.Values{
			"file": []string{in},
		},
	}
	got := s.processLoadRequest(state)
	if strings.HasPrefix(strings.ToUpper(got), "SAF_") {
		t.Fatalf("resultado de carga inesperado con alias file: %q", got)
	}
	if !strings.HasPrefix(got, "entrada_alias.txt:") {
		t.Fatalf("formato inesperado con alias file: %q", got)
	}
}

func TestProcessSignAndSaveRequestAliasDataReturnsSaf09WithoutUI(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	state := &ProtocolState{
		Action: "signandsave",
		Params: url.Values{
			"data":      []string{base64.StdEncoding.EncodeToString([]byte("hola"))},
			"signFormat": []string{"CAdES"},
			"fileName":  []string{"salida_alias"},
		},
	}
	got := strings.TrimSpace(s.processSignAndSaveRequest(state))
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_09:") {
		t.Fatalf("se esperaba SAF_09 con data/signFormat aliases y sin UI, obtenido: %q", got)
	}
}

func TestProcessLoadRequestCancelReturnsCancel(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", &UI{})
	state := &ProtocolState{
		Action: "load",
		Params: url.Values{},
	}

	oldLoadDialog := loadDialogFunc
	loadDialogFunc = func(initialPath string, exts string, multi bool) ([]string, bool, error) {
		return nil, true, nil
	}
	defer func() { loadDialogFunc = oldLoadDialog }()

	got := s.processLoadRequest(state)
	if got != "CANCEL" {
		t.Fatalf("se esperaba CANCEL al cancelar carga, obtenido: %q", got)
	}
}

func TestProcessLoadRequestWithUIUsesDialogEvenWithFilePath(t *testing.T) {
	tmp := t.TempDir()
	in := filepath.Join(tmp, "entrada.txt")
	if err := os.WriteFile(in, []byte("hola"), 0o644); err != nil {
		t.Fatalf("no se pudo preparar fichero: %v", err)
	}

	s := NewWebSocketServer([]int{63117}, "", &UI{})
	state := &ProtocolState{
		Action: "load",
		Params: url.Values{
			"filePath": []string{in},
		},
	}

	oldLoadDialog := loadDialogFunc
	dialogCalls := 0
	loadDialogFunc = func(initialPath string, exts string, multi bool) ([]string, bool, error) {
		dialogCalls++
		return []string{in}, false, nil
	}
	defer func() { loadDialogFunc = oldLoadDialog }()

	got := s.processLoadRequest(state)
	if strings.HasPrefix(strings.ToUpper(got), "SAF_") || got == "CANCEL" {
		t.Fatalf("resultado inesperado: %q", got)
	}
	if dialogCalls != 1 {
		t.Fatalf("se esperaba apertura de dialogo (1), obtenido: %d", dialogCalls)
	}
}

func TestProcessLoadRequestAliasMultiEnablesMultiLoad(t *testing.T) {
	tmp := t.TempDir()
	in := filepath.Join(tmp, "entrada_multi.txt")
	if err := os.WriteFile(in, []byte("hola"), 0o644); err != nil {
		t.Fatalf("no se pudo preparar fichero: %v", err)
	}

	s := NewWebSocketServer([]int{63117}, "", &UI{})
	state := &ProtocolState{
		Action: "load",
		Params: url.Values{
			"filePath": []string{in},
			"multi":    []string{"true"},
		},
	}

	oldLoadDialog := loadDialogFunc
	seenMulti := false
	loadDialogFunc = func(initialPath string, exts string, multi bool) ([]string, bool, error) {
		seenMulti = multi
		return []string{in}, false, nil
	}
	defer func() { loadDialogFunc = oldLoadDialog }()

	got := s.processLoadRequest(state)
	if strings.HasPrefix(strings.ToUpper(got), "SAF_") || got == "CANCEL" {
		t.Fatalf("resultado inesperado: %q", got)
	}
	if !seenMulti {
		t.Fatalf("se esperaba multi=true con alias 'multi'")
	}
}

func TestProcessSelectCertRequestCancelReturnsCancel(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", &UI{})
	state := &ProtocolState{Action: "selectcert"}

	oldGetCerts := getSystemCertificatesFunc
	oldSelectCertDialog := selectCertDialogFunc
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{
			{
				ID:      "cert1",
				CanSign: true,
				Content: []byte{0x30, 0x82, 0x01, 0x0A},
				Subject: map[string]string{"CN": "Test Cert"},
				Issuer:  map[string]string{"CN": "Test CA"},
			},
		}, nil
	}
	selectCertDialogFunc = func(certs []protocol.Certificate) (int, bool, error) {
		return -1, true, nil
	}
	defer func() {
		getSystemCertificatesFunc = oldGetCerts
		selectCertDialogFunc = oldSelectCertDialog
	}()

	got := s.processSelectCertRequest(state)
	if got != "CANCEL" {
		t.Fatalf("se esperaba CANCEL al cancelar seleccion de certificado, obtenido: %q", got)
	}
}

func TestProcessSelectCertRequestStickyReuse(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", &UI{})

	oldGetCerts := getSystemCertificatesFunc
	oldSelectCertDialog := selectCertDialogFunc
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{
			{
				ID:      "cert1",
				CanSign: true,
				Content: []byte{0x30, 0x82, 0x01, 0x0A},
				Subject: map[string]string{"CN": "Cert Uno"},
				Issuer:  map[string]string{"CN": "CA"},
			},
		}, nil
	}
	dialogCalls := 0
	selectCertDialogFunc = func(certs []protocol.Certificate) (int, bool, error) {
		dialogCalls++
		return 0, false, nil
	}
	defer func() {
		getSystemCertificatesFunc = oldGetCerts
		selectCertDialogFunc = oldSelectCertDialog
	}()

	stateSticky := &ProtocolState{
		Action: "selectcert",
		Params: url.Values{
			"sticky": []string{"true"},
		},
	}
	got1 := s.processSelectCertRequest(stateSticky)
	if strings.HasPrefix(strings.ToUpper(got1), "SAF_") || got1 == "CANCEL" {
		t.Fatalf("resultado inesperado primera seleccion sticky: %q", got1)
	}

	got2 := s.processSelectCertRequest(stateSticky)
	if strings.HasPrefix(strings.ToUpper(got2), "SAF_") || got2 == "CANCEL" {
		t.Fatalf("resultado inesperado segunda seleccion sticky: %q", got2)
	}
	if dialogCalls != 1 {
		t.Fatalf("se esperaba 1 invocacion de dialogo por sticky reuse, obtenido: %d", dialogCalls)
	}
}

func TestProcessSelectCertRequestDefaultKeyStorePKCS11FiltersCandidates(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	state := &ProtocolState{
		Action: "selectcert",
		Params: url.Values{
			"defaultKeyStore": []string{"PKCS11"},
		},
	}

	oldGetCerts := getSystemCertificatesFunc
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{
			{
				ID:      "sys1",
				CanSign: true,
				Source:  "system",
				Content: []byte{0x30, 0x82, 0x01, 0x01},
				Subject: map[string]string{"CN": "System Cert"},
				Issuer:  map[string]string{"CN": "CA"},
			},
			{
				ID:      "pkcs1",
				CanSign: true,
				Source:  "smartcard",
				Content: []byte{0x30, 0x82, 0x01, 0x02},
				Subject: map[string]string{"CN": "Token Cert"},
				Issuer:  map[string]string{"CN": "CA"},
			},
		}, nil
	}
	defer func() { getSystemCertificatesFunc = oldGetCerts }()

	got := s.processSelectCertRequest(state)
	want := base64.URLEncoding.EncodeToString([]byte{0x30, 0x82, 0x01, 0x02})
	if got != want {
		t.Fatalf("defaultKeyStore=PKCS11 debe priorizar cert smartcard, obtenido=%q esperado=%q", got, want)
	}
}

func TestProcessSelectCertRequestDefaultKeyStoreUnknownFallsBack(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	state := &ProtocolState{
		Action: "selectcert",
		Params: url.Values{
			"defaultKeyStore": []string{"UNSUPPORTED_STORE"},
		},
	}

	oldGetCerts := getSystemCertificatesFunc
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{
			{
				ID:      "sys1",
				CanSign: true,
				Source:  "system",
				Content: []byte{0x30, 0x82, 0x01, 0x0A},
				Subject: map[string]string{"CN": "System Cert"},
				Issuer:  map[string]string{"CN": "CA"},
			},
			{
				ID:      "pkcs1",
				CanSign: true,
				Source:  "smartcard",
				Content: []byte{0x30, 0x82, 0x01, 0x0B},
				Subject: map[string]string{"CN": "Token Cert"},
				Issuer:  map[string]string{"CN": "CA"},
			},
		}, nil
	}
	defer func() { getSystemCertificatesFunc = oldGetCerts }()

	got := s.processSelectCertRequest(state)
	want := base64.URLEncoding.EncodeToString([]byte{0x30, 0x82, 0x01, 0x0A})
	if got != want {
		t.Fatalf("defaultKeyStore desconocido debe mantener comportamiento previo (fallback), obtenido=%q esperado=%q", got, want)
	}
}

func TestProcessSelectCertRequestDefaultKeyStoreLowercaseAlias(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	state := &ProtocolState{
		Action: "selectcert",
		Params: url.Values{
			"defaultkeystore": []string{"pkcs11"},
		},
	}

	oldGetCerts := getSystemCertificatesFunc
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{
			{
				ID:      "sys1",
				CanSign: true,
				Source:  "system",
				Content: []byte{0x30, 0x82, 0x01, 0x21},
				Subject: map[string]string{"CN": "System Cert"},
				Issuer:  map[string]string{"CN": "CA"},
			},
			{
				ID:      "pkcs1",
				CanSign: true,
				Source:  "dnie",
				Content: []byte{0x30, 0x82, 0x01, 0x22},
				Subject: map[string]string{"CN": "DNIe Cert"},
				Issuer:  map[string]string{"CN": "CA"},
			},
		}, nil
	}
	defer func() { getSystemCertificatesFunc = oldGetCerts }()

	got := s.processSelectCertRequest(state)
	want := base64.URLEncoding.EncodeToString([]byte{0x30, 0x82, 0x01, 0x22})
	if got != want {
		t.Fatalf("alias defaultkeystore debe funcionar como defaultKeyStore, obtenido=%q esperado=%q", got, want)
	}
}

func TestLoadCertificatesForStateUsesPKCS11ModuleHints(t *testing.T) {
	state := &ProtocolState{
		Action: "selectcert",
		Params: url.Values{
			"defaultKeyStore":    []string{"PKCS11"},
			"defaultKeyStoreLib": []string{"/opt/lib/p11a.so;/opt/lib/p11b.so"},
		},
	}

	oldGet := getSystemCertificatesFunc
	oldGetWithOpts := getSystemCertificatesWithOptionsFunc
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		t.Fatalf("no debe usar carga general cuando hay defaultKeyStoreLib para PKCS11")
		return nil, nil
	}
	getSystemCertificatesWithOptionsFunc = func(opts certstore.Options) ([]protocol.Certificate, error) {
		if !opts.IncludePKCS11 {
			t.Fatalf("con defaultKeyStore=PKCS11 debe incluir escaneo PKCS11")
		}
		if len(opts.PKCS11ModulePaths) != 2 ||
			opts.PKCS11ModulePaths[0] != "/opt/lib/p11a.so" ||
			opts.PKCS11ModulePaths[1] != "/opt/lib/p11b.so" {
			t.Fatalf("hints PKCS11 inesperados: %#v", opts.PKCS11ModulePaths)
		}
		return []protocol.Certificate{{ID: "c1", Source: "smartcard", CanSign: true, Content: []byte{0x01}}}, nil
	}
	defer func() {
		getSystemCertificatesFunc = oldGet
		getSystemCertificatesWithOptionsFunc = oldGetWithOpts
	}()

	certs, err := loadCertificatesForState(state)
	if err != nil || len(certs) != 1 || certs[0].ID != "c1" {
		t.Fatalf("resultado inesperado loadCertificatesForState: certs=%#v err=%v", certs, err)
	}
}

func TestLoadCertificatesForStateNonPKCS11StoreSkipsPKCS11Scan(t *testing.T) {
	state := &ProtocolState{
		Action: "selectcert",
		Params: url.Values{
			"defaultKeyStore": []string{"MOZ_UNI"},
		},
	}

	oldGet := getSystemCertificatesFunc
	oldGetWithOpts := getSystemCertificatesWithOptionsFunc
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		t.Fatalf("no debe usar loader por defecto si hay preferencia de store explicita")
		return nil, nil
	}
	getSystemCertificatesWithOptionsFunc = func(opts certstore.Options) ([]protocol.Certificate, error) {
		if opts.IncludePKCS11 {
			t.Fatalf("con MOZ_UNI debe omitirse escaneo PKCS11")
		}
		return []protocol.Certificate{{ID: "c2", CanSign: true, Content: []byte{0x02}}}, nil
	}
	defer func() {
		getSystemCertificatesFunc = oldGet
		getSystemCertificatesWithOptionsFunc = oldGetWithOpts
	}()

	certs, err := loadCertificatesForState(state)
	if err != nil || len(certs) != 1 || certs[0].ID != "c2" {
		t.Fatalf("resultado inesperado loadCertificatesForState con skip PKCS11: certs=%#v err=%v", certs, err)
	}
}

func TestLoadCertificatesForStatePKCS11HintsErrorFallsBackToDefaultLoader(t *testing.T) {
	state := &ProtocolState{
		Action: "selectcert",
		Params: url.Values{
			"defaultKeyStore":    []string{"PKCS11"},
			"defaultKeyStoreLib": []string{"/opt/lib/p11.so"},
		},
	}

	oldGet := getSystemCertificatesFunc
	oldGetWithOpts := getSystemCertificatesWithOptionsFunc
	getSystemCertificatesWithOptionsFunc = func(opts certstore.Options) ([]protocol.Certificate, error) {
		return nil, errors.New("forced options loader error")
	}
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{{ID: "fallback", CanSign: true, Content: []byte{0x03}}}, nil
	}
	defer func() {
		getSystemCertificatesFunc = oldGet
		getSystemCertificatesWithOptionsFunc = oldGetWithOpts
	}()

	certs, err := loadCertificatesForState(state)
	if err != nil || len(certs) != 1 || certs[0].ID != "fallback" {
		t.Fatalf("debe hacer fallback al loader por defecto ante error, certs=%#v err=%v", certs, err)
	}
}

func TestLoadCertificatesForStateUnknownStoreUsesDefaultLoader(t *testing.T) {
	state := &ProtocolState{
		Action: "selectcert",
		Params: url.Values{
			"defaultKeyStore": []string{"CUSTOM_UNKNOWN"},
		},
	}

	oldGet := getSystemCertificatesFunc
	oldGetWithOpts := getSystemCertificatesWithOptionsFunc
	getSystemCertificatesWithOptionsFunc = func(opts certstore.Options) ([]protocol.Certificate, error) {
		t.Fatalf("store desconocido debe mantener loader por defecto para compatibilidad")
		return nil, nil
	}
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{{ID: "def", CanSign: true, Content: []byte{0x04}}}, nil
	}
	defer func() {
		getSystemCertificatesFunc = oldGet
		getSystemCertificatesWithOptionsFunc = oldGetWithOpts
	}()

	certs, err := loadCertificatesForState(state)
	if err != nil || len(certs) != 1 || certs[0].ID != "def" {
		t.Fatalf("resultado inesperado para store desconocido: certs=%#v err=%v", certs, err)
	}
}

func TestLoadCertificatesForStateDisableOpeningExternalStoresSkipsPKCS11(t *testing.T) {
	props := base64.StdEncoding.EncodeToString([]byte("filter=disableopeningexternalstores\n"))
	state := &ProtocolState{
		Action: "selectcert",
		Params: url.Values{
			"properties": []string{props},
		},
	}

	oldGet := getSystemCertificatesFunc
	oldGetWithOpts := getSystemCertificatesWithOptionsFunc
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		t.Fatalf("con disableopeningexternalstores debe usar loader con opciones para excluir PKCS11")
		return nil, nil
	}
	getSystemCertificatesWithOptionsFunc = func(opts certstore.Options) ([]protocol.Certificate, error) {
		if opts.IncludePKCS11 {
			t.Fatalf("disableopeningexternalstores debe desactivar escaneo PKCS11")
		}
		return []protocol.Certificate{{ID: "sys", Source: "system", CanSign: true, Content: []byte{0x31}}}, nil
	}
	defer func() {
		getSystemCertificatesFunc = oldGet
		getSystemCertificatesWithOptionsFunc = oldGetWithOpts
	}()

	certs, err := loadCertificatesForState(state)
	if err != nil || len(certs) != 1 || certs[0].ID != "sys" {
		t.Fatalf("resultado inesperado con disableopeningexternalstores: certs=%#v err=%v", certs, err)
	}
}

func TestLoadCertificatesForStateDisableOpeningExternalStoresDoesNotOverrideExplicitPKCS11(t *testing.T) {
	props := base64.StdEncoding.EncodeToString([]byte("filter=disableopeningexternalstores\n"))
	state := &ProtocolState{
		Action: "selectcert",
		Params: url.Values{
			"defaultKeyStore": []string{"PKCS11"},
			"properties":      []string{props},
		},
	}

	oldGet := getSystemCertificatesFunc
	oldGetWithOpts := getSystemCertificatesWithOptionsFunc
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{{ID: "pk", Source: "smartcard", CanSign: true, Content: []byte{0x32}}}, nil
	}
	getSystemCertificatesWithOptionsFunc = func(opts certstore.Options) ([]protocol.Certificate, error) {
		t.Fatalf("sin defaultKeyStoreLib no debe forzar loader con opciones")
		return nil, nil
	}
	defer func() {
		getSystemCertificatesFunc = oldGet
		getSystemCertificatesWithOptionsFunc = oldGetWithOpts
	}()

	certs, err := loadCertificatesForState(state)
	if err != nil || len(certs) != 1 || certs[0].ID != "pk" {
		t.Fatalf("resultado inesperado con PKCS11 explicito + disableopeningexternalstores: certs=%#v err=%v", certs, err)
	}
}

func TestSplitStoreLibHintsNormalizesAndDeduplicates(t *testing.T) {
	got := splitStoreLibHints(" /a/p11.so ; /b/p11.so, /a/p11.so ,, ; ")
	if len(got) != 2 || got[0] != "/a/p11.so" || got[1] != "/b/p11.so" {
		t.Fatalf("normalizacion de hints inesperada: %#v", got)
	}
}

func TestResolvePKCS11ModuleHintsSupportsAliasKeys(t *testing.T) {
	state := &ProtocolState{
		Action: "selectcert",
		Params: url.Values{
			"defaultkeystore":    []string{"pkcs11"},
			"defaultkeystorelib": []string{"/x/a.so,/x/b.so"},
		},
	}
	got := resolvePKCS11ModuleHints(state)
	if len(got) != 2 || got[0] != "/x/a.so" || got[1] != "/x/b.so" {
		t.Fatalf("hints desde alias defaultkeystorelib inesperados: %#v", got)
	}
}

func TestSummarizeModuleHints(t *testing.T) {
	got := summarizeModuleHints([]string{"/a/one.so", "/b/two.so", "/c/three.so", "/d/four.so"})
	if got != "one.so,two.so,three.so,+1 more" {
		t.Fatalf("resumen de hints inesperado: %q", got)
	}
}

func TestHasPKCS11Certificates(t *testing.T) {
	if hasPKCS11Certificates([]protocol.Certificate{
		{ID: "a", Source: "system"},
		{ID: "b", Source: "dnie"},
	}) != true {
		t.Fatalf("debe detectar fuente dnie como PKCS11")
	}
	if hasPKCS11Certificates([]protocol.Certificate{
		{ID: "a", Source: "system"},
		{ID: "b", Source: "windows"},
	}) != false {
		t.Fatalf("no debe detectar PKCS11 donde no lo hay")
	}
}

func TestLoadCertificatesForStatePKCS11HintsWithoutTokenCertsRetriesDefaultDiscovery(t *testing.T) {
	state := &ProtocolState{
		Action: "selectcert",
		Params: url.Values{
			"defaultKeyStore":    []string{"PKCS11"},
			"defaultKeyStoreLib": []string{"/opt/lib/nonworking-p11.so"},
		},
	}

	oldGet := getSystemCertificatesFunc
	oldGetWithOpts := getSystemCertificatesWithOptionsFunc
	getSystemCertificatesWithOptionsFunc = func(opts certstore.Options) ([]protocol.Certificate, error) {
		// Simula que el módulo indicado no aporta certificados PKCS11, solo sistema.
		return []protocol.Certificate{
			{ID: "sys1", Source: "system", CanSign: true, Content: []byte{0x10}},
		}, nil
	}
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		// Descubrimiento por defecto sí encuentra token.
		return []protocol.Certificate{
			{ID: "pk1", Source: "smartcard", CanSign: true, Content: []byte{0x20}},
		}, nil
	}
	defer func() {
		getSystemCertificatesFunc = oldGet
		getSystemCertificatesWithOptionsFunc = oldGetWithOpts
	}()

	certs, err := loadCertificatesForState(state)
	if err != nil || len(certs) != 1 || certs[0].ID != "pk1" {
		t.Fatalf("debe reintentar descubrimiento PKCS11 por defecto si hints no devuelven token, certs=%#v err=%v", certs, err)
	}
}

func TestProcessProtocolRequestLoadWithoutPathReturnsSaf25(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	got := strings.TrimSpace(s.processProtocolRequest("afirma://load?id=1"))
	if !strings.HasPrefix(strings.ToUpper(got), "SAF_25:") {
		t.Fatalf("se esperaba SAF_25 para load sin filePath, obtenido: %q", got)
	}
}

func TestStorageCheckReturnsOK(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	req := httptest.NewRequest(http.MethodGet, "/afirma-signature-storage/StorageService?op=check", nil)
	rr := httptest.NewRecorder()

	s.handleStorageService(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status inesperado: %d", rr.Code)
	}
	if strings.TrimSpace(rr.Body.String()) != "OK" {
		t.Fatalf("respuesta inesperada: %q", rr.Body.String())
	}
}

func TestRetrieveMissingIDReturnsErr06(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	req := httptest.NewRequest(http.MethodGet, "/afirma-signature-retriever/RetrieveService?op=get&v=1_0&id=no-existe", nil)
	rr := httptest.NewRecorder()

	s.handleRetrieveService(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status inesperado: %d", rr.Code)
	}
	got := strings.TrimSpace(rr.Body.String())
	if !strings.HasPrefix(strings.ToLower(got), "err-06") {
		t.Fatalf("se esperaba ERR-06, obtenido: %q", got)
	}
}

func TestPutThenGetAndDelete(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)

	form := url.Values{}
	form.Set("op", "put")
	form.Set("v", "1_0")
	form.Set("id", "abc123")
	form.Set("dat", "FIRMA_B64")

	putReq := httptest.NewRequest(http.MethodPost, "/afirma-signature-storage/StorageService", strings.NewReader(form.Encode()))
	putReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	putRR := httptest.NewRecorder()
	s.handleStorageService(putRR, putReq)

	if strings.TrimSpace(putRR.Body.String()) != "OK" {
		t.Fatalf("put no devolvio OK: %q", putRR.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/afirma-signature-retriever/RetrieveService?op=get&v=1_0&id=abc123", nil)
	getRR := httptest.NewRecorder()
	s.handleRetrieveService(getRR, getReq)
	if strings.TrimSpace(getRR.Body.String()) != "FIRMA_B64" {
		t.Fatalf("get devolvio valor inesperado: %q", getRR.Body.String())
	}

	getReq2 := httptest.NewRequest(http.MethodGet, "/afirma-signature-retriever/RetrieveService?op=get&v=1_0&id=abc123", nil)
	getRR2 := httptest.NewRecorder()
	s.handleRetrieveService(getRR2, getReq2)
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(getRR2.Body.String())), "err-06") {
		t.Fatalf("tras leer una vez, se esperaba ERR-06: %q", getRR2.Body.String())
	}
}

func TestExtractMessageSessionID(t *testing.T) {
	tests := []struct {
		msg  string
		want string
	}{
		{"echo=-idsession=abc123@EOF", "abc123"},
		{"echo=-idSession=abc124@EOF", "abc124"},
		{"afirma://sign?id=1&idsession=sess01&v=4", "sess01"},
		{"afirma://sign?id=1&idSession=sess02&v=4", "sess02"},
		{"afirma://sign?id=1&v=4", ""},
	}
	for _, tc := range tests {
		if got := extractMessageSessionID(tc.msg); got != tc.want {
			t.Fatalf("extractMessageSessionID(%q)=%q want=%q", tc.msg, got, tc.want)
		}
	}
}

func TestIsLoopbackRemoteAddr(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:12345", true},
		{"[::1]:12345", true},
		{"localhost:12345", true},
		{"192.168.1.10:12345", false},
		{"example.com:12345", false},
	}
	for _, tc := range cases {
		if got := isLoopbackRemoteAddr(tc.addr); got != tc.want {
			t.Fatalf("isLoopbackRemoteAddr(%q)=%v want=%v", tc.addr, got, tc.want)
		}
	}
}

func TestParseBoolParam(t *testing.T) {
	if !parseBoolParam("false", "1") {
		t.Fatalf("se esperaba true para valor 1")
	}
	if !parseBoolParam("", "TRUE") {
		t.Fatalf("se esperaba true para valor TRUE")
	}
	if parseBoolParam("", "0", "no") {
		t.Fatalf("se esperaba false para valores negativos")
	}
}

func TestDecodeProtocolProperties(t *testing.T) {
	raw := "filter=subject.contains:juan\nmandatoryCertSelection=false\n"
	b64 := base64.StdEncoding.EncodeToString([]byte(raw))
	props := decodeProtocolProperties(b64)
	if props["filter"] != "subject.contains:juan" {
		t.Fatalf("filter inesperado: %#v", props)
	}
	if props["mandatoryCertSelection"] != "false" {
		t.Fatalf("mandatoryCertSelection inesperado: %#v", props)
	}

	rawPlain := "filter=issuer.contains:acme\\nheadless=true"
	propsPlain := decodeProtocolProperties(rawPlain)
	if propsPlain["filter"] != "issuer.contains:acme" || propsPlain["headless"] != "true" {
		t.Fatalf("properties plano inesperado: %#v", propsPlain)
	}

	rawURL := "filter%3Dsubject.contains%3Aana%0AmandatoryCertSelection%3Dfalse"
	propsURL := decodeProtocolProperties(rawURL)
	if propsURL["filter"] != "subject.contains:ana" || propsURL["mandatoryCertSelection"] != "false" {
		t.Fatalf("properties urlencoded inesperado: %#v", propsURL)
	}
}

func TestDecodeAutoFirmaB64AcceptsPlusAsSpace(t *testing.T) {
	// Bytes {0x03,0xE0,0x00} encode to "A+AA"; legacy query decoding may convert '+' to space.
	raw := "A+AA"
	legacy := strings.ReplaceAll(raw, "+", " ")
	got, err := decodeAutoFirmaB64(legacy)
	if err != nil {
		t.Fatalf("decodeAutoFirmaB64 no deberia fallar con '+' como espacio: %v", err)
	}
	if len(got) != 3 || got[0] != 0x03 || got[1] != 0xE0 || got[2] != 0x00 {
		t.Fatalf("contenido inesperado: %v", got)
	}
}

func TestApplySelectCertFiltersSubjectContains(t *testing.T) {
	certs := []protocol.Certificate{
		{
			ID:      "1",
			Subject: map[string]string{"CN": "Juan Perez"},
			Issuer:  map[string]string{"CN": "ACME CA"},
			Content: []byte{0x01},
			CanSign: true,
		},
		{
			ID:      "2",
			Subject: map[string]string{"CN": "Maria Lopez"},
			Issuer:  map[string]string{"CN": "ACME CA"},
			Content: []byte{0x02},
			CanSign: true,
		},
	}
	propsBody := "filter=subject.contains:juan\n"
	state := &ProtocolState{
		Action: "selectcert",
		Params: url.Values{
			"properties": []string{base64.StdEncoding.EncodeToString([]byte(propsBody))},
		},
	}
	filtered, opts := applySelectCertFilters(certs, state)
	if opts.forceAutoSelection {
		t.Fatalf("no se esperaba auto-seleccion forzada")
	}
	if len(filtered) != 1 || filtered[0].ID != "1" {
		t.Fatalf("filtrado inesperado: %#v", filtered)
	}
}

func TestApplySelectCertFiltersReadsPropertiesCaseInsensitive(t *testing.T) {
	certs := []protocol.Certificate{
		{
			ID:      "1",
			Subject: map[string]string{"CN": "Juan Perez"},
			Issuer:  map[string]string{"CN": "ACME CA"},
			Content: []byte{0x01},
			CanSign: true,
		},
		{
			ID:      "2",
			Subject: map[string]string{"CN": "Maria Lopez"},
			Issuer:  map[string]string{"CN": "ACME CA"},
			Content: []byte{0x02},
			CanSign: true,
		},
	}
	propsBody := "filter=subject.contains:maria\n"
	state := &ProtocolState{
		Action: "selectcert",
		Params: url.Values{
			"Properties": []string{base64.StdEncoding.EncodeToString([]byte(propsBody))},
		},
	}
	filtered, _ := applySelectCertFilters(certs, state)
	if len(filtered) != 1 || filtered[0].ID != "2" {
		t.Fatalf("filtrado case-insensitive de properties inesperado: %#v", filtered)
	}
}

func TestApplySelectCertFiltersPropertyKeysCaseInsensitive(t *testing.T) {
	certs := []protocol.Certificate{
		{
			ID:      "1",
			Subject: map[string]string{"CN": "Juan Perez"},
			Issuer:  map[string]string{"CN": "ACME CA"},
			Content: []byte{0x01},
			CanSign: true,
		},
	}
	propsBody := "FILTER=subject.contains:juan\nMANDATORYCERTSELECTION=false\n"
	state := &ProtocolState{
		Action: "selectcert",
		Params: url.Values{
			"properties": []string{base64.StdEncoding.EncodeToString([]byte(propsBody))},
		},
	}
	filtered, opts := applySelectCertFilters(certs, state)
	if len(filtered) != 1 || filtered[0].ID != "1" {
		t.Fatalf("filtro con clave FILTER no aplicado correctamente: %#v", filtered)
	}
	if !opts.autoSelectWhenSingle {
		t.Fatalf("mandatoryCertSelection case-insensitive debe activar autoSelectWhenSingle")
	}
}

func TestProcessSelectCertRequestMandatorySelectionFalseSkipsDialog(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", &UI{})
	state := &ProtocolState{
		Action: "selectcert",
		Params: url.Values{
			"properties": []string{
				base64.StdEncoding.EncodeToString([]byte("mandatoryCertSelection=false\nfilter=subject.contains:juan\n")),
			},
		},
	}

	oldGetCerts := getSystemCertificatesFunc
	oldSelectCertDialog := selectCertDialogFunc
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{
			{
				ID:      "cert1",
				CanSign: true,
				Content: []byte{0x30, 0x82, 0x01, 0x0A},
				Subject: map[string]string{"CN": "Juan Cert"},
				Issuer:  map[string]string{"CN": "CA"},
			},
			{
				ID:      "cert2",
				CanSign: true,
				Content: []byte{0x30, 0x82, 0x01, 0x0B},
				Subject: map[string]string{"CN": "Otro"},
				Issuer:  map[string]string{"CN": "CA"},
			},
		}, nil
	}
	dialogCalls := 0
	selectCertDialogFunc = func(certs []protocol.Certificate) (int, bool, error) {
		dialogCalls++
		return 0, false, nil
	}
	defer func() {
		getSystemCertificatesFunc = oldGetCerts
		selectCertDialogFunc = oldSelectCertDialog
	}()

	got := s.processSelectCertRequest(state)
	if strings.HasPrefix(strings.ToUpper(got), "SAF_") || got == "CANCEL" {
		t.Fatalf("resultado inesperado: %q", got)
	}
	if dialogCalls != 0 {
		t.Fatalf("no debia abrir dialogo con mandatoryCertSelection=false, llamadas=%d", dialogCalls)
	}
}

func TestProcessSelectCertRequestMandatorySelectionFalseWithMultipleShowsDialog(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", &UI{})
	state := &ProtocolState{
		Action: "selectcert",
		Params: url.Values{
			"properties": []string{
				base64.StdEncoding.EncodeToString([]byte("mandatoryCertSelection=false\n")),
			},
		},
	}

	oldGetCerts := getSystemCertificatesFunc
	oldSelectCertDialog := selectCertDialogFunc
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{
			{
				ID:      "cert1",
				CanSign: true,
				Content: []byte{0x30, 0x82, 0x01, 0x0A},
				Subject: map[string]string{"CN": "Juan Cert"},
				Issuer:  map[string]string{"CN": "CA"},
			},
			{
				ID:      "cert2",
				CanSign: true,
				Content: []byte{0x30, 0x82, 0x01, 0x0B},
				Subject: map[string]string{"CN": "Otro Cert"},
				Issuer:  map[string]string{"CN": "CA"},
			},
		}, nil
	}
	dialogCalls := 0
	selectCertDialogFunc = func(certs []protocol.Certificate) (int, bool, error) {
		dialogCalls++
		return 1, false, nil
	}
	defer func() {
		getSystemCertificatesFunc = oldGetCerts
		selectCertDialogFunc = oldSelectCertDialog
	}()

	got := s.processSelectCertRequest(state)
	if strings.HasPrefix(strings.ToUpper(got), "SAF_") || got == "CANCEL" {
		t.Fatalf("resultado inesperado: %q", got)
	}
	if dialogCalls != 1 {
		t.Fatalf("con mandatoryCertSelection=false y varios certificados debe abrir dialogo, llamadas=%d", dialogCalls)
	}
}
