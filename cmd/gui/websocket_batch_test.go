// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"autofirma-host/pkg/protocol"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProcessProtocolRequestBatchLocalJSONNeedsUI(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)

	oldGetCerts := getSystemCertificatesFunc
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{{ID: "c1", CanSign: true, Content: []byte{0x01}}}, nil
	}
	defer func() { getSystemCertificatesFunc = oldGetCerts }()

	batchJSON := `{"format":"CAdES","algorithm":"SHA256withRSA","singlesigns":[{"id":"d1","datareference":"` +
		base64.StdEncoding.EncodeToString([]byte("abc")) + `"}]}`
	uri := "afirma://batch?id=abc&jsonbatch=true&localBatchProcess=true&dat=" +
		base64.StdEncoding.EncodeToString([]byte(batchJSON))
	out := s.processProtocolRequest(uri)
	if !strings.HasPrefix(out, "SAF_09:") {
		t.Fatalf("se esperaba SAF_09 sin UI en batch, obtenido: %s", out)
	}
}

func TestProcessProtocolRequestBatchLocalJSONSuccess(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", &UI{})

	oldGetCerts := getSystemCertificatesFunc
	oldSelectCert := selectCertDialogFunc
	oldSignData := signDataFunc
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{{ID: "c1", CanSign: true, Content: []byte{0x30, 0x82, 0x01}}}, nil
	}
	selectCertDialogFunc = func(certs []protocol.Certificate) (int, bool, error) {
		return 0, false, nil
	}
	signDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		return base64.StdEncoding.EncodeToString([]byte("SIG")), nil
	}
	defer func() {
		getSystemCertificatesFunc = oldGetCerts
		selectCertDialogFunc = oldSelectCert
		signDataFunc = oldSignData
	}()

	batchJSON := `{"format":"CAdES","algorithm":"SHA256withRSA","singlesigns":[{"id":"d1","datareference":"` +
		base64.StdEncoding.EncodeToString([]byte("abc")) + `"}]}`
	uri := "afirma://batch?id=abc&jsonbatch=true&localBatchProcess=true&dat=" +
		base64.StdEncoding.EncodeToString([]byte(batchJSON))
	out := s.processProtocolRequest(uri)

	raw, err := base64.StdEncoding.DecodeString(out)
	if err != nil {
		t.Fatalf("respuesta batch no base64: %v - %s", err, out)
	}
	var resp batchResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("respuesta batch no JSON valido: %v", err)
	}
	if len(resp.Signs) != 1 {
		t.Fatalf("numero de resultados inesperado: %d", len(resp.Signs))
	}
	if resp.Signs[0].ID != "d1" || resp.Signs[0].Result != batchResultDone || resp.Signs[0].Signature == "" {
		t.Fatalf("resultado batch inesperado: %#v", resp.Signs[0])
	}
}

func TestProcessProtocolRequestBatchStopOnErrorMarksSkipped(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", &UI{})

	oldGetCerts := getSystemCertificatesFunc
	oldSelectCert := selectCertDialogFunc
	oldSignData := signDataFunc
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{{ID: "c1", CanSign: true, Content: []byte{0x30, 0x82, 0x01}}}, nil
	}
	selectCertDialogFunc = func(certs []protocol.Certificate) (int, bool, error) {
		return 0, false, nil
	}
	call := 0
	signDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		call++
		if call == 2 {
			return "", json.Unmarshal([]byte("{"), &struct{}{}) // force error
		}
		return base64.StdEncoding.EncodeToString([]byte("SIG")), nil
	}
	defer func() {
		getSystemCertificatesFunc = oldGetCerts
		selectCertDialogFunc = oldSelectCert
		signDataFunc = oldSignData
	}()

	dataRef := base64.StdEncoding.EncodeToString([]byte("abc"))
	batchJSON := `{"stoponerror":true,"format":"CAdES","algorithm":"SHA256withRSA","singlesigns":[` +
		`{"id":"d1","datareference":"` + dataRef + `"},` +
		`{"id":"d2","datareference":"` + dataRef + `"},` +
		`{"id":"d3","datareference":"` + dataRef + `"}` +
		`]}`
	uri := "afirma://batch?id=abc&jsonbatch=true&localBatchProcess=true&dat=" +
		base64.StdEncoding.EncodeToString([]byte(batchJSON))
	out := s.processProtocolRequest(uri)

	raw, err := base64.StdEncoding.DecodeString(out)
	if err != nil {
		t.Fatalf("respuesta batch no base64: %v - %s", err, out)
	}
	var resp batchResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("respuesta batch no JSON valido: %v", err)
	}
	if len(resp.Signs) != 3 {
		t.Fatalf("numero de resultados inesperado: %d", len(resp.Signs))
	}
	if resp.Signs[0].Result != batchResultSkipped {
		t.Fatalf("el primer resultado debe quedar SKIPPED cuando hay stoponerror: %#v", resp.Signs[0])
	}
	if resp.Signs[1].Result != batchResultError {
		t.Fatalf("el segundo resultado debe ser ERROR_PRE: %#v", resp.Signs[1])
	}
	if resp.Signs[2].Result != batchResultSkipped {
		t.Fatalf("el tercero debe ser SKIPPED por stoponerror: %#v", resp.Signs[2])
	}
}

func TestProcessProtocolRequestBatchLocalXMLSuccess(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", &UI{})

	oldGetCerts := getSystemCertificatesFunc
	oldSelectCert := selectCertDialogFunc
	oldSignData := signDataFunc
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{{ID: "c1", CanSign: true, Content: []byte{0x30, 0x82, 0x01}}}, nil
	}
	selectCertDialogFunc = func(certs []protocol.Certificate) (int, bool, error) {
		return 0, false, nil
	}
	signDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		return base64.StdEncoding.EncodeToString([]byte("SIG")), nil
	}
	defer func() {
		getSystemCertificatesFunc = oldGetCerts
		selectCertDialogFunc = oldSelectCert
		signDataFunc = oldSignData
	}()

	batchXML := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<signbatch stoponerror="false" algorithm="SHA256withRSA">` +
		`<singlesign Id="d1">` +
		`<datasource>` + base64.StdEncoding.EncodeToString([]byte("abc")) + `</datasource>` +
		`<format>CAdES</format>` +
		`<suboperation>sign</suboperation>` +
		`<extraparams></extraparams>` +
		`</singlesign>` +
		`</signbatch>`
	uri := "afirma://batch?id=abc&localBatchProcess=true&dat=" +
		base64.StdEncoding.EncodeToString([]byte(batchXML))
	out := s.processProtocolRequest(uri)

	raw, err := base64.StdEncoding.DecodeString(out)
	if err != nil {
		t.Fatalf("respuesta batch xml no base64: %v - %s", err, out)
	}
	var resp xmlBatchResponse
	if err := xml.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("respuesta batch xml no valida: %v", err)
	}
	if len(resp.Signs) != 1 || resp.Signs[0].ID != "d1" || resp.Signs[0].Result != batchResultDone {
		t.Fatalf("resultado xml inesperado: %#v", resp.Signs)
	}
}

func TestProcessProtocolRequestBatchLocalXMLStopOnError(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", &UI{})

	oldGetCerts := getSystemCertificatesFunc
	oldSelectCert := selectCertDialogFunc
	oldSignData := signDataFunc
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{{ID: "c1", CanSign: true, Content: []byte{0x30, 0x82, 0x01}}}, nil
	}
	selectCertDialogFunc = func(certs []protocol.Certificate) (int, bool, error) {
		return 0, false, nil
	}
	call := 0
	signDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		call++
		if call == 2 {
			return "", json.Unmarshal([]byte("{"), &struct{}{})
		}
		return base64.StdEncoding.EncodeToString([]byte("SIG")), nil
	}
	defer func() {
		getSystemCertificatesFunc = oldGetCerts
		selectCertDialogFunc = oldSelectCert
		signDataFunc = oldSignData
	}()

	dataRef := base64.StdEncoding.EncodeToString([]byte("abc"))
	batchXML := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<signbatch stoponerror="true" algorithm="SHA256withRSA">` +
		`<singlesign Id="d1"><datasource>` + dataRef + `</datasource><format>CAdES</format><suboperation>sign</suboperation></singlesign>` +
		`<singlesign Id="d2"><datasource>` + dataRef + `</datasource><format>CAdES</format><suboperation>sign</suboperation></singlesign>` +
		`<singlesign Id="d3"><datasource>` + dataRef + `</datasource><format>CAdES</format><suboperation>sign</suboperation></singlesign>` +
		`</signbatch>`
	uri := "afirma://batch?id=abc&localBatchProcess=true&dat=" +
		base64.StdEncoding.EncodeToString([]byte(batchXML))
	out := s.processProtocolRequest(uri)

	raw, err := base64.StdEncoding.DecodeString(out)
	if err != nil {
		t.Fatalf("respuesta batch xml no base64: %v - %s", err, out)
	}
	var resp xmlBatchResponse
	if err := xml.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("respuesta batch xml no valida: %v", err)
	}
	if len(resp.Signs) != 3 {
		t.Fatalf("numero de resultados inesperado: %d", len(resp.Signs))
	}
	if resp.Signs[0].Result != batchResultSkipped || resp.Signs[1].Result != batchResultError || resp.Signs[2].Result != batchResultSkipped {
		t.Fatalf("resultado stopOnError xml inesperado: %#v", resp.Signs)
	}
}

func TestResolveBatchDataReferenceFromFilePath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "in.bin")
	if err := os.WriteFile(p, []byte("abc"), 0o600); err != nil {
		t.Fatalf("error preparando fichero temporal: %v", err)
	}
	data, err := resolveBatchDataReference(p)
	if err != nil {
		t.Fatalf("resolveBatchDataReference file error: %v", err)
	}
	if string(data) != "abc" {
		t.Fatalf("contenido file inesperado: %q", string(data))
	}
}

func TestResolveBatchDataReferenceUnsupportedScheme(t *testing.T) {
	if _, err := resolveBatchDataReference("mailto:test@example.com"); err == nil {
		t.Fatalf("se esperaba error en esquema no soportado")
	}
}

func TestProcessProtocolRequestBatchRemoteJSONSuccess(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", &UI{})

	oldGetCerts := getSystemCertificatesFunc
	oldSelectCert := selectCertDialogFunc
	oldHTTP := batchHTTPPostFunc
	oldPK1 := signPKCS1Func
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{{ID: "c1", CanSign: true, Content: []byte{0x30, 0x82, 0x01}}}, nil
	}
	selectCertDialogFunc = func(certs []protocol.Certificate) (int, bool, error) { return 0, false, nil }
	signPKCS1Func = func(preSignData []byte, certificateID string, algorithm string) (string, error) {
		return base64.StdEncoding.EncodeToString([]byte("PK1")), nil
	}

	call := 0
	batchHTTPPostFunc = func(rawURL string) ([]byte, error) {
		call++
		u, _ := url.Parse(rawURL)
		q := u.Query()
		if call == 1 {
			pre := map[string]interface{}{
				"td": map[string]interface{}{
					"format": "CAdES",
					"signinfo": []map[string]interface{}{
						{"id": "d1", "params": map[string]string{"PRE": base64.StdEncoding.EncodeToString([]byte("predata"))}},
					},
				},
				"results": []map[string]string{
					{"id": "d2", "result": batchResultError, "description": "fallo pre"},
				},
			}
			return json.Marshal(pre)
		}
		if q.Get("tridata") == "" {
			t.Fatalf("post sin tridata")
		}
		return []byte(`{"signs":[{"id":"d1","result":"DONE_AND_SAVED"},{"id":"d2","result":"ERROR_PRE"}]}`), nil
	}
	defer func() {
		getSystemCertificatesFunc = oldGetCerts
		selectCertDialogFunc = oldSelectCert
		batchHTTPPostFunc = oldHTTP
		signPKCS1Func = oldPK1
	}()

	batchJSON := `{"algorithm":"SHA256withRSA","singlesigns":[{"id":"d1","datareference":"` +
		base64.StdEncoding.EncodeToString([]byte("abc")) + `"},{"id":"d2","datareference":"` +
		base64.StdEncoding.EncodeToString([]byte("abc")) + `"}]}`
	uri := "afirma://batch?id=abc&jsonbatch=true&localBatchProcess=false&batchpresignerurl=https%3A%2F%2Fpre.example&batchpostsignerurl=https%3A%2F%2Fpost.example&dat=" +
		base64.StdEncoding.EncodeToString([]byte(batchJSON))
	out := s.processProtocolRequest(uri)

	raw, err := base64.StdEncoding.DecodeString(out)
	if err != nil {
		t.Fatalf("respuesta batch remoto no base64: %v - %s", err, out)
	}
	var resp batchResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("respuesta batch remoto no JSON valido: %v", err)
	}
	if len(resp.Signs) != 2 || resp.Signs[0].ID != "d1" {
		t.Fatalf("resultado remoto inesperado: %#v", resp.Signs)
	}
}

func TestProcessProtocolRequestBatchRemoteJSONRequiresURLs(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", &UI{})

	oldGetCerts := getSystemCertificatesFunc
	oldSelectCert := selectCertDialogFunc
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{{ID: "c1", CanSign: true, Content: []byte{0x30, 0x82, 0x01}}}, nil
	}
	selectCertDialogFunc = func(certs []protocol.Certificate) (int, bool, error) { return 0, false, nil }
	defer func() {
		getSystemCertificatesFunc = oldGetCerts
		selectCertDialogFunc = oldSelectCert
	}()

	batchJSON := `{"algorithm":"SHA256withRSA","singlesigns":[{"id":"d1","datareference":"` +
		base64.StdEncoding.EncodeToString([]byte("abc")) + `"}]}`
	uri := "afirma://batch?id=abc&jsonbatch=true&localBatchProcess=false&dat=" +
		base64.StdEncoding.EncodeToString([]byte(batchJSON))
	out := s.processProtocolRequest(uri)
	if !strings.HasPrefix(out, "SAF_03:") {
		t.Fatalf("se esperaba SAF_03 sin urls pre/post, obtenido: %s", out)
	}
}

func TestProcessProtocolRequestBatchRemoteXMLSuccess(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", &UI{})

	oldGetCerts := getSystemCertificatesFunc
	oldSelectCert := selectCertDialogFunc
	oldHTTP := batchHTTPPostFunc
	oldPK1 := signPKCS1Func
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{{ID: "c1", CanSign: true, Content: []byte{0x30, 0x82, 0x01}}}, nil
	}
	selectCertDialogFunc = func(certs []protocol.Certificate) (int, bool, error) { return 0, false, nil }
	signPKCS1Func = func(preSignData []byte, certificateID string, algorithm string) (string, error) {
		return base64.StdEncoding.EncodeToString([]byte("PK1")), nil
	}

	call := 0
	batchHTTPPostFunc = func(rawURL string) ([]byte, error) {
		call++
		if call == 1 {
			return []byte(`<xml><firmas format="CAdES"><firma Id="d1"><param n="PRE">` +
				base64.StdEncoding.EncodeToString([]byte("predata")) +
				`</param></firma></firmas></xml>`), nil
		}
		return []byte(`<?xml version="1.0" encoding="UTF-8"?><signs><signresult id="d1" result="DONE_AND_SAVED" description=""/></signs>`), nil
	}
	defer func() {
		getSystemCertificatesFunc = oldGetCerts
		selectCertDialogFunc = oldSelectCert
		batchHTTPPostFunc = oldHTTP
		signPKCS1Func = oldPK1
	}()

	batchXML := `<?xml version="1.0" encoding="UTF-8"?><signbatch stoponerror="false" algorithm="SHA256withRSA"><singlesign Id="d1"><datasource>` +
		base64.StdEncoding.EncodeToString([]byte("abc")) +
		`</datasource><format>CAdES</format><suboperation>sign</suboperation></singlesign></signbatch>`
	uri := "afirma://batch?id=abc&localBatchProcess=false&batchpresignerurl=https%3A%2F%2Fpre.example&batchpostsignerurl=https%3A%2F%2Fpost.example&dat=" +
		base64.StdEncoding.EncodeToString([]byte(batchXML))
	out := s.processProtocolRequest(uri)

	raw, err := base64.StdEncoding.DecodeString(out)
	if err != nil {
		t.Fatalf("respuesta batch remoto xml no base64: %v - %s", err, out)
	}
	if !strings.Contains(string(raw), `<signresult id="d1" result="DONE_AND_SAVED"`) {
		t.Fatalf("resultado remoto xml inesperado: %s", string(raw))
	}
}

func TestProcessProtocolRequestBatchRemoteJSONPre400ReturnsSaf03(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", &UI{})

	oldGetCerts := getSystemCertificatesFunc
	oldSelectCert := selectCertDialogFunc
	oldHTTP := batchHTTPPostFunc
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{{ID: "c1", CanSign: true, Content: []byte{0x30, 0x82, 0x01}}}, nil
	}
	selectCertDialogFunc = func(certs []protocol.Certificate) (int, bool, error) { return 0, false, nil }
	batchHTTPPostFunc = func(rawURL string) ([]byte, error) {
		return nil, &batchHTTPError{StatusCode: 400, Body: "bad req"}
	}
	defer func() {
		getSystemCertificatesFunc = oldGetCerts
		selectCertDialogFunc = oldSelectCert
		batchHTTPPostFunc = oldHTTP
	}()

	batchJSON := `{"algorithm":"SHA256withRSA","singlesigns":[{"id":"d1","datareference":"` +
		base64.StdEncoding.EncodeToString([]byte("abc")) + `"}]}`
	uri := "afirma://batch?id=abc&jsonbatch=true&localBatchProcess=false&batchpresignerurl=https%3A%2F%2Fpre.example&batchpostsignerurl=https%3A%2F%2Fpost.example&dat=" +
		base64.StdEncoding.EncodeToString([]byte(batchJSON))
	out := s.processProtocolRequest(uri)
	if !strings.HasPrefix(out, "SAF_03:") {
		t.Fatalf("se esperaba SAF_03 en prefirma 400, obtenido: %s", out)
	}
}

func TestProcessProtocolRequestBatchRemoteJSONPre5xxReturnsSaf27(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", &UI{})

	oldGetCerts := getSystemCertificatesFunc
	oldSelectCert := selectCertDialogFunc
	oldHTTP := batchHTTPPostFunc
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{{ID: "c1", CanSign: true, Content: []byte{0x30, 0x82, 0x01}}}, nil
	}
	selectCertDialogFunc = func(certs []protocol.Certificate) (int, bool, error) { return 0, false, nil }
	batchHTTPPostFunc = func(rawURL string) ([]byte, error) {
		return nil, &batchHTTPError{StatusCode: 500, Body: "server err"}
	}
	defer func() {
		getSystemCertificatesFunc = oldGetCerts
		selectCertDialogFunc = oldSelectCert
		batchHTTPPostFunc = oldHTTP
	}()

	batchJSON := `{"algorithm":"SHA256withRSA","singlesigns":[{"id":"d1","datareference":"` +
		base64.StdEncoding.EncodeToString([]byte("abc")) + `"}]}`
	uri := "afirma://batch?id=abc&jsonbatch=true&localBatchProcess=false&batchpresignerurl=https%3A%2F%2Fpre.example&batchpostsignerurl=https%3A%2F%2Fpost.example&dat=" +
		base64.StdEncoding.EncodeToString([]byte(batchJSON))
	out := s.processProtocolRequest(uri)
	if !strings.HasPrefix(out, "SAF_27:") {
		t.Fatalf("se esperaba SAF_27 en prefirma 5xx, obtenido: %s", out)
	}
}

func TestProcessProtocolRequestBatchRemoteJSONPostErrProtocolReturnsSaf27(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", &UI{})

	oldGetCerts := getSystemCertificatesFunc
	oldSelectCert := selectCertDialogFunc
	oldHTTP := batchHTTPPostFunc
	oldPK1 := signPKCS1Func
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{{ID: "c1", CanSign: true, Content: []byte{0x30, 0x82, 0x01}}}, nil
	}
	selectCertDialogFunc = func(certs []protocol.Certificate) (int, bool, error) { return 0, false, nil }
	signPKCS1Func = func(preSignData []byte, certificateID string, algorithm string) (string, error) {
		return base64.StdEncoding.EncodeToString([]byte("PK1")), nil
	}

	call := 0
	batchHTTPPostFunc = func(rawURL string) ([]byte, error) {
		call++
		if call == 1 {
			pre := map[string]interface{}{
				"td": map[string]interface{}{
					"format": "CAdES",
					"signinfo": []map[string]interface{}{
						{"id": "d1", "params": map[string]string{"PRE": base64.StdEncoding.EncodeToString([]byte("predata"))}},
					},
				},
			}
			return json.Marshal(pre)
		}
		return []byte("ERR-21: detalle"), nil
	}
	defer func() {
		getSystemCertificatesFunc = oldGetCerts
		selectCertDialogFunc = oldSelectCert
		batchHTTPPostFunc = oldHTTP
		signPKCS1Func = oldPK1
	}()

	batchJSON := `{"algorithm":"SHA256withRSA","singlesigns":[{"id":"d1","datareference":"` +
		base64.StdEncoding.EncodeToString([]byte("abc")) + `"}]}`
	uri := "afirma://batch?id=abc&jsonbatch=true&localBatchProcess=false&batchpresignerurl=https%3A%2F%2Fpre.example&batchpostsignerurl=https%3A%2F%2Fpost.example&dat=" +
		base64.StdEncoding.EncodeToString([]byte(batchJSON))
	out := s.processProtocolRequest(uri)
	if !strings.HasPrefix(out, "SAF_27:") {
		t.Fatalf("se esperaba SAF_27 con ERR- en post, obtenido: %s", out)
	}
}

func TestExecuteBatchSingleUsesGlobalSubOperationCosign(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", &UI{})

	oldSign := signDataFunc
	oldCoSign := coSignDataFunc
	oldCounter := counterSignDataFunc
	signDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		t.Fatalf("no debe invocarse signData en suboperation=cosign")
		return "", nil
	}
	counterSignDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		t.Fatalf("no debe invocarse countersign en suboperation=cosign")
		return "", nil
	}
	coSignDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		return base64.StdEncoding.EncodeToString([]byte("COSIG")), nil
	}
	defer func() {
		signDataFunc = oldSign
		coSignDataFunc = oldCoSign
		counterSignDataFunc = oldCounter
	}()

	item := batchSingleEntry{
		ID:      "d1",
		DataRef: base64.StdEncoding.EncodeToString([]byte("sig-previa")),
	}
	req := &batchRequest{
		SubOp:     "cosign",
		Format:    "CAdES",
		Algorithm: "SHA256withRSA",
	}
	res := s.executeBatchSingle(item, req, "c1", map[string]string{})
	if res.Result != batchResultDone || strings.TrimSpace(res.Signature) == "" {
		t.Fatalf("resultado inesperado: %#v", res)
	}
}

func TestExecuteBatchSingleEntrySubOperationOverridesGlobal(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", &UI{})

	oldSign := signDataFunc
	oldCoSign := coSignDataFunc
	oldCounter := counterSignDataFunc
	coSignDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		t.Fatalf("no debe invocarse cosign cuando singlesign pide sign")
		return "", nil
	}
	counterSignDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		t.Fatalf("no debe invocarse countersign cuando singlesign pide sign")
		return "", nil
	}
	signDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		return base64.StdEncoding.EncodeToString([]byte("SIG")), nil
	}
	defer func() {
		signDataFunc = oldSign
		coSignDataFunc = oldCoSign
		counterSignDataFunc = oldCounter
	}()

	item := batchSingleEntry{
		ID:      "d1",
		SubOp:   "sign",
		DataRef: base64.StdEncoding.EncodeToString([]byte("abc")),
	}
	req := &batchRequest{
		SubOp:     "cosign",
		Format:    "CAdES",
		Algorithm: "SHA256withRSA",
	}
	res := s.executeBatchSingle(item, req, "c1", map[string]string{})
	if res.Result != batchResultDone || strings.TrimSpace(res.Signature) == "" {
		t.Fatalf("resultado inesperado: %#v", res)
	}
}

func TestExecuteBatchSingleUnsupportedSubOperation(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", &UI{})
	item := batchSingleEntry{
		ID:      "d1",
		SubOp:   "firmar-otra-cosa",
		DataRef: base64.StdEncoding.EncodeToString([]byte("abc")),
	}
	req := &batchRequest{
		Format:    "CAdES",
		Algorithm: "SHA256withRSA",
	}
	res := s.executeBatchSingle(item, req, "c1", map[string]string{})
	if res.Result != batchResultError {
		t.Fatalf("se esperaba ERROR_PRE por suboperation no soportada: %#v", res)
	}
	if !strings.Contains(strings.ToLower(res.Description), "no soportada") {
		t.Fatalf("descripcion inesperada: %q", res.Description)
	}
}

func TestExecuteBatchSingleUsesCounterSignSubOperation(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", &UI{})

	oldSign := signDataFunc
	oldCoSign := coSignDataFunc
	oldCounter := counterSignDataFunc
	signDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		t.Fatalf("no debe invocarse signData en suboperation=countersign")
		return "", nil
	}
	coSignDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		t.Fatalf("no debe invocarse cosign en suboperation=countersign")
		return "", nil
	}
	counterSignDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		return base64.StdEncoding.EncodeToString([]byte("COUNTERSIG")), nil
	}
	defer func() {
		signDataFunc = oldSign
		coSignDataFunc = oldCoSign
		counterSignDataFunc = oldCounter
	}()

	item := batchSingleEntry{
		ID:      "d1",
		SubOp:   "countersign",
		DataRef: base64.StdEncoding.EncodeToString([]byte("sig-previa")),
	}
	req := &batchRequest{
		Format:    "CAdES",
		Algorithm: "SHA256withRSA",
	}
	res := s.executeBatchSingle(item, req, "c1", map[string]string{})
	if res.Result != batchResultDone || strings.TrimSpace(res.Signature) == "" {
		t.Fatalf("resultado inesperado: %#v", res)
	}
}
