// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"autofirma-host/pkg/protocol"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func optionAsString(options map[string]interface{}, key string) string {
	if options == nil {
		return ""
	}
	raw, ok := options[key]
	if !ok || raw == nil {
		return ""
	}
	s, ok := raw.(string)
	if !ok {
		return ""
	}
	return s
}

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

func TestProcessProtocolRequestBatchLocalJSONHeadlessWithoutUIWorks(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)

	oldGetCerts := getSystemCertificatesFunc
	oldSignData := signDataFunc
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{{ID: "c1", CanSign: true, Content: []byte{0x01}}}, nil
	}
	signDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		return base64.StdEncoding.EncodeToString([]byte("SIG")), nil
	}
	defer func() {
		getSystemCertificatesFunc = oldGetCerts
		signDataFunc = oldSignData
	}()

	props := base64.StdEncoding.EncodeToString([]byte("headless=true\nmandatoryCertSelection=false\n"))
	batchJSON := `{"format":"CAdES","algorithm":"SHA256withRSA","singlesigns":[{"id":"d1","datareference":"` +
		base64.StdEncoding.EncodeToString([]byte("abc")) + `"}]}`
	uri := "afirma://batch?id=abc&jsonbatch=true&localBatchProcess=true&properties=" +
		url.QueryEscape(props) + "&dat=" + base64.StdEncoding.EncodeToString([]byte(batchJSON))
	out := s.processProtocolRequest(uri)

	raw, err := base64.StdEncoding.DecodeString(out)
	if err != nil {
		t.Fatalf("respuesta batch no base64: %v - %s", err, out)
	}
	var resp batchResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("respuesta batch no JSON valido: %v", err)
	}
	if len(resp.Signs) != 1 || resp.Signs[0].Result != batchResultDone {
		t.Fatalf("resultado batch headless sin UI inesperado: %#v", resp.Signs)
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

func TestSelectBatchSigningCertificateDefaultKeyStorePKCS11(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", &UI{})
	state := &ProtocolState{
		Action: "batch",
		Params: url.Values{
			"defaultKeyStore": []string{"PKCS11"},
		},
	}

	oldGetCerts := getSystemCertificatesFunc
	oldSelectCert := selectCertDialogFunc
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{
			{ID: "sys1", CanSign: true, Source: "system", Content: []byte{0x01}},
			{ID: "pkcs1", CanSign: true, Source: "smartcard", Content: []byte{0x02}},
		}, nil
	}
	selectCertDialogFunc = func(certs []protocol.Certificate) (int, bool, error) {
		if len(certs) != 1 || certs[0].ID != "pkcs1" {
			t.Fatalf("defaultKeyStore=PKCS11 debe filtrar a smartcard/dnie, obtenido: %#v", certs)
		}
		return 0, false, nil
	}
	defer func() {
		getSystemCertificatesFunc = oldGetCerts
		selectCertDialogFunc = oldSelectCert
	}()

	cert, errCode := s.selectBatchSigningCertificate(state)
	if errCode != "" {
		t.Fatalf("error inesperado seleccionando cert batch: %s", errCode)
	}
	if cert.ID != "pkcs1" {
		t.Fatalf("certificado batch seleccionado inesperado: %s", cert.ID)
	}
}

func TestSelectBatchSigningCertificateStickyCaseInsensitiveParam(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", nil)
	s.stickyID = "cert2"
	state := &ProtocolState{
		Action: "batch",
		Params: url.Values{
			"Sticky": []string{"true"},
		},
	}

	oldGetCerts := getSystemCertificatesFunc
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{
			{ID: "cert1", CanSign: true, Source: "system", Content: []byte{0x01}},
			{ID: "cert2", CanSign: true, Source: "system", Content: []byte{0x02}},
		}, nil
	}
	defer func() { getSystemCertificatesFunc = oldGetCerts }()

	cert, errCode := s.selectBatchSigningCertificate(state)
	if errCode != "" {
		t.Fatalf("error inesperado reutilizando sticky en batch: %s", errCode)
	}
	if cert.ID != "cert2" {
		t.Fatalf("se esperaba reutilizar sticky cert2, obtenido: %s", cert.ID)
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

func TestParseBatchXMLRequestReadsGlobalExtraParams(t *testing.T) {
	raw := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<signbatch stoponerror="false" algorithm="SHA256withRSA">
  <extraparams>pin=5555\npolicyIdentifier=urn:test</extraparams>
  <singlesign Id="d1">
    <datasource>AAA=</datasource>
    <format>CAdES</format>
    <suboperation>sign</suboperation>
  </singlesign>
</signbatch>`)
	req, err := parseBatchXMLRequest(raw)
	if err != nil {
		t.Fatalf("error parseando XML batch: %v", err)
	}
	if strings.TrimSpace(req.ExtraParams) == "" || !strings.Contains(req.ExtraParams, "pin=5555") {
		t.Fatalf("extraparams global no parseado: %q", req.ExtraParams)
	}
}

func TestParseBatchJSONRequestSupportsCamelCaseCompat(t *testing.T) {
	raw := []byte(`{
  "stopOnError": true,
  "subOperation": "cosign",
  "extraParams": "pin=1111",
  "singleSigns": [
    {
      "id": "d1",
      "subOperation": "sign",
      "dataReference": "QUJD",
      "format": "CAdES",
      "algorithm": "SHA256withRSA",
      "extraParams": "policyIdentifier=urn:test"
    }
  ]
}`)
	req, err := parseBatchJSONRequest(raw)
	if err != nil {
		t.Fatalf("error parseando JSON batch camelCase: %v", err)
	}
	if !req.StopOnError {
		t.Fatalf("stopOnError camelCase no aplicado")
	}
	if req.SubOp != "cosign" {
		t.Fatalf("subOperation camelCase no aplicado: %q", req.SubOp)
	}
	if req.ExtraParams != "pin=1111" {
		t.Fatalf("extraParams camelCase no aplicado: %q", req.ExtraParams)
	}
	if len(req.SingleSigns) != 1 || req.SingleSigns[0].DataRef != "QUJD" || req.SingleSigns[0].SubOp != "sign" {
		t.Fatalf("singleSigns camelCase no aplicado: %#v", req.SingleSigns)
	}
	if req.SingleSigns[0].ExtraParams != "policyIdentifier=urn:test" {
		t.Fatalf("singleSign.extraParams camelCase no aplicado: %q", req.SingleSigns[0].ExtraParams)
	}
}

func TestBuildBatchRemoteSignOptionsNormalizesPerSignIDs(t *testing.T) {
	state := &ProtocolState{Params: url.Values{}}
	req := &batchRequest{
		ExtraParams: "pin=1111",
		SingleSigns: []batchSingleEntry{
			{ID: "Doc-A", ExtraParams: "policyIdentifier=urn:doca"},
		},
	}
	global, perSign := buildBatchRemoteSignOptions(state, req)
	if optionAsString(global, "_pin") != "1111" {
		t.Fatalf("pin global no aplicado: %#v", global)
	}
	if len(perSign) != 1 {
		t.Fatalf("perSign inesperado: %#v", perSign)
	}
	opts, ok := perSign["doc-a"]
	if !ok {
		t.Fatalf("id de perSign no normalizado: %#v", perSign)
	}
	if optionAsString(opts, "policyIdentifier") != "urn:doca" {
		t.Fatalf("extraParams por firma no aplicado: %#v", opts)
	}
}

func TestSignTriphaseDataAppliesPerSignOptionsBySignIDFallback(t *testing.T) {
	oldPK1 := signPKCS1WithOptionsFunc
	defer func() { signPKCS1WithOptionsFunc = oldPK1 }()

	var gotPolicy string
	signPKCS1WithOptionsFunc = func(preSignData []byte, certificateID string, algorithm string, options map[string]interface{}) (string, error) {
		gotPolicy = optionAsString(options, "policyIdentifier")
		return base64.StdEncoding.EncodeToString([]byte("PK1")), nil
	}

	td := &triphaseDataResponse{
		Format: "CAdES",
		SignInfo: []triphaseSignInfoDTO{
			{
				ID:     "",
				SignID: "Doc-42",
				Params: map[string]string{
					"PRE": base64.StdEncoding.EncodeToString([]byte("predata")),
				},
			},
		},
	}
	_, err := signTriphaseData(td, "c1", "SHA256withRSA", map[string]interface{}{}, map[string]map[string]interface{}{
		"doc-42": map[string]interface{}{"policyIdentifier": "urn:doc42"},
	})
	if err != nil {
		t.Fatalf("error inesperado firmando triphase: %v", err)
	}
	if gotPolicy != "urn:doc42" {
		t.Fatalf("fallback por signid no aplicado: %q", gotPolicy)
	}
}

func TestSignTriphaseDataXMLAppliesPerSignOptionsBySignIDFallback(t *testing.T) {
	oldPK1 := signPKCS1WithOptionsFunc
	defer func() { signPKCS1WithOptionsFunc = oldPK1 }()

	var gotPolicy string
	signPKCS1WithOptionsFunc = func(preSignData []byte, certificateID string, algorithm string, options map[string]interface{}) (string, error) {
		gotPolicy = optionAsString(options, "policyIdentifier")
		return base64.StdEncoding.EncodeToString([]byte("PK1")), nil
	}

	raw := []byte(`<xml><firmas format="CAdES"><firma signid="Doc-XML-7"><param n="PRE">` +
		base64.StdEncoding.EncodeToString([]byte("predata")) +
		`</param></firma></firmas></xml>`)

	_, err := signTriphaseDataXML(raw, "c1", "SHA256withRSA", map[string]interface{}{}, map[string]map[string]interface{}{
		"doc-xml-7": map[string]interface{}{"policyIdentifier": "urn:xml7"},
	})
	if err != nil {
		t.Fatalf("error inesperado firmando triphase XML: %v", err)
	}
	if gotPolicy != "urn:xml7" {
		t.Fatalf("fallback por signid XML no aplicado: %q", gotPolicy)
	}
}

func TestProcessProtocolRequestBatchRemoteJSONSuccess(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", &UI{})

	oldGetCerts := getSystemCertificatesFunc
	oldSelectCert := selectCertDialogFunc
	oldHTTP := batchHTTPPostFunc
	oldPK1 := signPKCS1WithOptionsFunc
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{{ID: "c1", CanSign: true, Content: []byte{0x30, 0x82, 0x01}}}, nil
	}
	selectCertDialogFunc = func(certs []protocol.Certificate) (int, bool, error) { return 0, false, nil }
	signPKCS1WithOptionsFunc = func(preSignData []byte, certificateID string, algorithm string, options map[string]interface{}) (string, error) {
		if got := strings.TrimSpace(optionAsString(options, "_defaultKeyStore")); got != "PKCS11" {
			t.Fatalf("defaultKeyStore no propagado a PKCS1 trifasico: %q", got)
		}
		if got := strings.TrimSpace(optionAsString(options, "_defaultKeyStoreLib")); got != "/opt/lib/p11a.so" {
			t.Fatalf("defaultKeyStoreLib no propagado a PKCS1 trifasico: %q", got)
		}
		if got := strings.TrimSpace(optionAsString(options, "_pin")); got != "1234" {
			t.Fatalf("pin no propagado a PKCS1 trifasico: %q", got)
		}
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
		signPKCS1WithOptionsFunc = oldPK1
	}()

	batchJSON := `{"algorithm":"SHA256withRSA","singlesigns":[{"id":"d1","datareference":"` +
		base64.StdEncoding.EncodeToString([]byte("abc")) + `"},{"id":"d2","datareference":"` +
		base64.StdEncoding.EncodeToString([]byte("abc")) + `"}]}`
	uri := "afirma://batch?id=abc&jsonbatch=true&localBatchProcess=false&defaultKeyStore=PKCS11&defaultKeyStoreLib=%2Fopt%2Flib%2Fp11a.so&pin=1234&batchpresignerurl=https%3A%2F%2Fpre.example&batchpostsignerurl=https%3A%2F%2Fpost.example&dat=" +
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
	oldPK1 := signPKCS1WithOptionsFunc
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{{ID: "c1", CanSign: true, Content: []byte{0x30, 0x82, 0x01}}}, nil
	}
	selectCertDialogFunc = func(certs []protocol.Certificate) (int, bool, error) { return 0, false, nil }
	signPKCS1WithOptionsFunc = func(preSignData []byte, certificateID string, algorithm string, options map[string]interface{}) (string, error) {
		if got := strings.TrimSpace(optionAsString(options, "_defaultKeyStore")); got != "PKCS11" {
			t.Fatalf("defaultKeyStore no propagado a PKCS1 trifasico XML: %q", got)
		}
		if got := strings.TrimSpace(optionAsString(options, "_defaultKeyStoreLib")); got != "/opt/lib/p11xml.so" {
			t.Fatalf("defaultKeyStoreLib no propagado a PKCS1 trifasico XML: %q", got)
		}
		if got := strings.TrimSpace(optionAsString(options, "_pin")); got != "9876" {
			t.Fatalf("pin no propagado a PKCS1 trifasico XML: %q", got)
		}
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
		signPKCS1WithOptionsFunc = oldPK1
	}()

	batchXML := `<?xml version="1.0" encoding="UTF-8"?><signbatch stoponerror="false" algorithm="SHA256withRSA"><extraparams>pin=9876</extraparams><singlesign Id="d1"><datasource>` +
		base64.StdEncoding.EncodeToString([]byte("abc")) +
		`</datasource><format>CAdES</format><suboperation>sign</suboperation></singlesign></signbatch>`
	uri := "afirma://batch?id=abc&localBatchProcess=false&defaultKeyStore=PKCS11&defaultKeyStoreLib=%2Fopt%2Flib%2Fp11xml.so&batchpresignerurl=https%3A%2F%2Fpre.example&batchpostsignerurl=https%3A%2F%2Fpost.example&dat=" +
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
	oldPK1 := signPKCS1WithOptionsFunc
	getSystemCertificatesFunc = func() ([]protocol.Certificate, error) {
		return []protocol.Certificate{{ID: "c1", CanSign: true, Content: []byte{0x30, 0x82, 0x01}}}, nil
	}
	selectCertDialogFunc = func(certs []protocol.Certificate) (int, bool, error) { return 0, false, nil }
	signPKCS1WithOptionsFunc = func(preSignData []byte, certificateID string, algorithm string, options map[string]interface{}) (string, error) {
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
		signPKCS1WithOptionsFunc = oldPK1
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
	res := s.executeBatchSingle(nil, item, req, "c1", map[string]string{})
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
	res := s.executeBatchSingle(nil, item, req, "c1", map[string]string{})
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
	res := s.executeBatchSingle(nil, item, req, "c1", map[string]string{})
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
	res := s.executeBatchSingle(nil, item, req, "c1", map[string]string{})
	if res.Result != batchResultDone || strings.TrimSpace(res.Signature) == "" {
		t.Fatalf("resultado inesperado: %#v", res)
	}
}

func TestExecuteBatchSingleCounterSignAliasTreeSetsTarget(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", &UI{})

	oldSign := signDataFunc
	oldCoSign := coSignDataFunc
	oldCounter := counterSignDataFunc
	defer func() {
		signDataFunc = oldSign
		coSignDataFunc = oldCoSign
		counterSignDataFunc = oldCounter
	}()

	counterSignDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		if got := strings.TrimSpace(signOptionString(options, "target")); got != "tree" {
			t.Fatalf("target esperado tree para alias contrafirmar_arbol, obtenido: %q", got)
		}
		return base64.StdEncoding.EncodeToString([]byte("COUNTERSIG")), nil
	}
	signDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		t.Fatalf("no debe invocarse signData en suboperation=contrafirmar_arbol")
		return "", nil
	}
	coSignDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		t.Fatalf("no debe invocarse cosign en suboperation=contrafirmar_arbol")
		return "", nil
	}

	item := batchSingleEntry{
		ID:      "d1",
		SubOp:   "contrafirmar_arbol",
		DataRef: base64.StdEncoding.EncodeToString([]byte("sig-previa")),
	}
	req := &batchRequest{
		Format:    "CAdES",
		Algorithm: "SHA256withRSA",
	}
	res := s.executeBatchSingle(nil, item, req, "c1", map[string]string{})
	if res.Result != batchResultDone || strings.TrimSpace(res.Signature) == "" {
		t.Fatalf("resultado inesperado: %#v", res)
	}
}

func TestExecuteBatchSingleCounterSignAliasLeafsSetsTarget(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", &UI{})

	oldSign := signDataFunc
	oldCoSign := coSignDataFunc
	oldCounter := counterSignDataFunc
	defer func() {
		signDataFunc = oldSign
		coSignDataFunc = oldCoSign
		counterSignDataFunc = oldCounter
	}()

	counterSignDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		if got := strings.TrimSpace(signOptionString(options, "target")); got != "leafs" {
			t.Fatalf("target esperado leafs para alias contrafirmar_hojas, obtenido: %q", got)
		}
		return base64.StdEncoding.EncodeToString([]byte("COUNTERSIG")), nil
	}
	signDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		t.Fatalf("no debe invocarse signData en suboperation=contrafirmar_hojas")
		return "", nil
	}
	coSignDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		t.Fatalf("no debe invocarse cosign en suboperation=contrafirmar_hojas")
		return "", nil
	}

	item := batchSingleEntry{
		ID:      "d1",
		SubOp:   "contrafirmar_hojas",
		DataRef: base64.StdEncoding.EncodeToString([]byte("sig-previa")),
	}
	req := &batchRequest{
		Format:    "CAdES",
		Algorithm: "SHA256withRSA",
	}
	res := s.executeBatchSingle(nil, item, req, "c1", map[string]string{})
	if res.Result != batchResultDone || strings.TrimSpace(res.Signature) == "" {
		t.Fatalf("resultado inesperado: %#v", res)
	}
}

func TestExecuteBatchSingleCounterSignAliasDoesNotOverrideExplicitTarget(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", &UI{})

	oldSign := signDataFunc
	oldCoSign := coSignDataFunc
	oldCounter := counterSignDataFunc
	defer func() {
		signDataFunc = oldSign
		coSignDataFunc = oldCoSign
		counterSignDataFunc = oldCounter
	}()

	counterSignDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		if got := strings.TrimSpace(signOptionString(options, "target")); got != "signers" {
			t.Fatalf("target explicito no debe sobreescribirse, obtenido: %q", got)
		}
		return base64.StdEncoding.EncodeToString([]byte("COUNTERSIG")), nil
	}
	signDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		t.Fatalf("no debe invocarse signData en este caso")
		return "", nil
	}
	coSignDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		t.Fatalf("no debe invocarse cosign en este caso")
		return "", nil
	}

	item := batchSingleEntry{
		ID:         "d1",
		SubOp:      "contrafirmar_arbol",
		ExtraParams: "target=signers",
		DataRef:    base64.StdEncoding.EncodeToString([]byte("sig-previa")),
	}
	req := &batchRequest{
		Format:    "CAdES",
		Algorithm: "SHA256withRSA",
	}
	res := s.executeBatchSingle(nil, item, req, "c1", map[string]string{})
	if res.Result != batchResultDone || strings.TrimSpace(res.Signature) == "" {
		t.Fatalf("resultado inesperado: %#v", res)
	}
}

func TestExecuteBatchSinglePropagatesStoreHintsToSigner(t *testing.T) {
	s := NewWebSocketServer([]int{63117}, "", &UI{})

	oldSign := signDataFunc
	oldCoSign := coSignDataFunc
	oldCounter := counterSignDataFunc
	defer func() {
		signDataFunc = oldSign
		coSignDataFunc = oldCoSign
		counterSignDataFunc = oldCounter
	}()

	signDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		get := func(k string) string {
			v, ok := options[k]
			if !ok || v == nil {
				return ""
			}
			s, ok := v.(string)
			if !ok {
				return ""
			}
			return strings.TrimSpace(s)
		}
		if got := get("_defaultKeyStore"); got != "PKCS11" {
			t.Fatalf("defaultKeyStore no propagado en batch: %q", got)
		}
		if got := get("_defaultKeyStoreLib"); got != "/opt/lib/a.so;/opt/lib/b.so" {
			t.Fatalf("defaultKeyStoreLib no propagado en batch: %q", got)
		}
		if got, ok := options["_disableOpeningExternalStores"].(bool); !ok || !got {
			t.Fatalf("disableopeningexternalstores no propagado en batch: %#v", options["_disableOpeningExternalStores"])
		}
		if pin != "2468" {
			t.Fatalf("pin no propagado al signFunc de batch: %q", pin)
		}
		return base64.StdEncoding.EncodeToString([]byte("SIG")), nil
	}
	coSignDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		t.Fatalf("no debe invocarse cosign en este caso")
		return "", nil
	}
	counterSignDataFunc = func(dataB64, certificateID, pin, format string, options map[string]interface{}) (string, error) {
		t.Fatalf("no debe invocarse countersign en este caso")
		return "", nil
	}

	state := &ProtocolState{
		Action: "batch",
		Params: mapToValues(map[string]string{
			"defaultKeyStore":    "PKCS11",
			"defaultKeyStoreLib": "/opt/lib/a.so;/opt/lib/b.so",
			"pin":                "2468",
			"properties":         mustB64("filter=disableopeningexternalstores\n"),
		}),
	}
	item := batchSingleEntry{
		ID:      "d1",
		SubOp:   "sign",
		DataRef: base64.StdEncoding.EncodeToString([]byte("abc")),
	}
	req := &batchRequest{
		Format:    "CAdES",
		Algorithm: "SHA256withRSA",
	}
	res := s.executeBatchSingle(state, item, req, "c1", map[string]string{})
	if res.Result != batchResultDone || strings.TrimSpace(res.Signature) == "" {
		t.Fatalf("resultado inesperado: %#v", res)
	}
}

func TestBatchHTTPPostWithRetryRetriesTransientHTTP5xx(t *testing.T) {
	oldHTTP := batchHTTPPostFunc
	defer func() { batchHTTPPostFunc = oldHTTP }()

	attempts := 0
	batchHTTPPostFunc = func(rawURL string) ([]byte, error) {
		attempts++
		if attempts < 3 {
			return nil, &batchHTTPError{StatusCode: 503, Body: "service unavailable"}
		}
		return []byte(`{"ok":true}`), nil
	}

	out, err := batchHTTPPostWithRetry("https://example.invalid/pre")
	if err != nil {
		t.Fatalf("se esperaba exito tras reintentos, error: %v", err)
	}
	if string(out) != `{"ok":true}` {
		t.Fatalf("salida inesperada: %q", string(out))
	}
	if attempts != 3 {
		t.Fatalf("se esperaban 3 intentos, obtenidos: %d", attempts)
	}
}

func TestBatchHTTPPostWithRetryDoesNotRetryOnHTTP400(t *testing.T) {
	oldHTTP := batchHTTPPostFunc
	defer func() { batchHTTPPostFunc = oldHTTP }()

	attempts := 0
	batchHTTPPostFunc = func(rawURL string) ([]byte, error) {
		attempts++
		return nil, &batchHTTPError{StatusCode: 400, Body: "bad request"}
	}

	_, err := batchHTTPPostWithRetry("https://example.invalid/pre")
	if err == nil {
		t.Fatalf("se esperaba error en HTTP 400")
	}
	if attempts != 1 {
		t.Fatalf("HTTP 400 no debe reintentarse, intentos=%d", attempts)
	}
}

func TestBatchHTTPPostWithRetryRetriesOnNetworkError(t *testing.T) {
	oldHTTP := batchHTTPPostFunc
	defer func() { batchHTTPPostFunc = oldHTTP }()

	attempts := 0
	batchHTTPPostFunc = func(rawURL string) ([]byte, error) {
		attempts++
		if attempts < 2 {
			return nil, errors.New("dial tcp timeout")
		}
		return []byte(`OK`), nil
	}

	out, err := batchHTTPPostWithRetry("https://example.invalid/post")
	if err != nil {
		t.Fatalf("se esperaba exito tras reintento de red, error: %v", err)
	}
	if string(out) != "OK" {
		t.Fatalf("salida inesperada: %q", string(out))
	}
	if attempts != 2 {
		t.Fatalf("se esperaban 2 intentos, obtenidos: %d", attempts)
	}
}

func TestResolveBatchHTTPTimeoutDefault(t *testing.T) {
	t.Setenv("AUTOFIRMA_BATCH_HTTP_TIMEOUT_MS", "")
	t.Setenv("AUTOFIRMA_BATCH_HTTP_TIMEOUT_SEC", "")
	got := resolveBatchHTTPTimeout()
	if got != 15*time.Second {
		t.Fatalf("timeout por defecto inesperado: %v", got)
	}
}

func TestResolveBatchHTTPTimeoutFromMS(t *testing.T) {
	t.Setenv("AUTOFIRMA_BATCH_HTTP_TIMEOUT_MS", "4500")
	t.Setenv("AUTOFIRMA_BATCH_HTTP_TIMEOUT_SEC", "")
	got := resolveBatchHTTPTimeout()
	if got != 4500*time.Millisecond {
		t.Fatalf("timeout ms inesperado: %v", got)
	}
}

func TestResolveBatchHTTPTimeoutFromSec(t *testing.T) {
	t.Setenv("AUTOFIRMA_BATCH_HTTP_TIMEOUT_MS", "")
	t.Setenv("AUTOFIRMA_BATCH_HTTP_TIMEOUT_SEC", "9")
	got := resolveBatchHTTPTimeout()
	if got != 9*time.Second {
		t.Fatalf("timeout sec inesperado: %v", got)
	}
}

func TestResolveBatchHTTPTimeoutInvalidFallsBackDefault(t *testing.T) {
	t.Setenv("AUTOFIRMA_BATCH_HTTP_TIMEOUT_MS", "abc")
	t.Setenv("AUTOFIRMA_BATCH_HTTP_TIMEOUT_SEC", "-1")
	got := resolveBatchHTTPTimeout()
	if got != 15*time.Second {
		t.Fatalf("timeout invalido debe volver a default, obtenido: %v", got)
	}
}

func TestResolveBatchHTTPMaxAttemptsDefault(t *testing.T) {
	t.Setenv("AUTOFIRMA_BATCH_HTTP_MAX_ATTEMPTS", "")
	got := resolveBatchHTTPMaxAttempts()
	if got != 3 {
		t.Fatalf("max attempts por defecto inesperado: %d", got)
	}
}

func TestResolveBatchHTTPMaxAttemptsFromEnv(t *testing.T) {
	t.Setenv("AUTOFIRMA_BATCH_HTTP_MAX_ATTEMPTS", "5")
	got := resolveBatchHTTPMaxAttempts()
	if got != 5 {
		t.Fatalf("max attempts inesperado desde env: %d", got)
	}
}

func TestResolveBatchHTTPMaxAttemptsInvalidFallsBackDefault(t *testing.T) {
	t.Setenv("AUTOFIRMA_BATCH_HTTP_MAX_ATTEMPTS", "0")
	got := resolveBatchHTTPMaxAttempts()
	if got != 3 {
		t.Fatalf("max attempts invalido debe volver a default, obtenido: %d", got)
	}
}

func TestResolveBatchHTTPMaxAttemptsCapped(t *testing.T) {
	t.Setenv("AUTOFIRMA_BATCH_HTTP_MAX_ATTEMPTS", "99")
	got := resolveBatchHTTPMaxAttempts()
	if got != 6 {
		t.Fatalf("max attempts debe caparse a 6, obtenido: %d", got)
	}
}

func TestBatchRemoteCircuitOpensAfterThresholdFailures(t *testing.T) {
	resetBatchRemoteBreakerForTests()
	t.Setenv("AUTOFIRMA_BATCH_BREAKER_THRESHOLD", "")
	key := "pre.example"
	now := time.Now()

	for i := 0; i < 2; i++ {
		batchRemoteRecordFailure(key, now)
		if _, blocked := batchRemoteIsOpen(key, now); blocked {
			t.Fatalf("el circuito no debe abrirse antes del umbral")
		}
	}

	batchRemoteRecordFailure(key, now)
	if until, blocked := batchRemoteIsOpen(key, now); !blocked || !until.After(now) {
		t.Fatalf("el circuito debe abrirse tras alcanzar el umbral")
	}
}

func TestBatchRemoteCircuitResetsOnSuccess(t *testing.T) {
	resetBatchRemoteBreakerForTests()
	t.Setenv("AUTOFIRMA_BATCH_BREAKER_THRESHOLD", "")
	key := "post.example"
	now := time.Now()

	for i := 0; i < 3; i++ {
		batchRemoteRecordFailure(key, now)
	}
	if _, blocked := batchRemoteIsOpen(key, now); !blocked {
		t.Fatalf("el circuito debe estar abierto antes del reset")
	}
	batchRemoteRecordSuccess(key)
	if _, blocked := batchRemoteIsOpen(key, now); blocked {
		t.Fatalf("el circuito debe cerrarse tras exito")
	}
}

func TestMapBatchRemoteHTTPErrorCircuitOpenReturnsSaf26(t *testing.T) {
	err := &batchCircuitOpenError{Key: "pre.example", OpenUntil: time.Now().Add(1 * time.Second)}
	msg := mapBatchRemoteHTTPError("prefirma", err)
	if !strings.HasPrefix(msg, "SAF_26:") {
		t.Fatalf("circuit open debe mapear a SAF_26, obtenido: %s", msg)
	}
}

func TestResolveBatchRemoteBreakerThresholdDefault(t *testing.T) {
	t.Setenv("AUTOFIRMA_BATCH_BREAKER_THRESHOLD", "")
	if got := resolveBatchRemoteBreakerThreshold(); got != 3 {
		t.Fatalf("threshold default inesperado: %d", got)
	}
}

func TestResolveBatchRemoteBreakerThresholdFromEnv(t *testing.T) {
	t.Setenv("AUTOFIRMA_BATCH_BREAKER_THRESHOLD", "5")
	if got := resolveBatchRemoteBreakerThreshold(); got != 5 {
		t.Fatalf("threshold desde env inesperado: %d", got)
	}
}

func TestResolveBatchRemoteBreakerThresholdCapped(t *testing.T) {
	t.Setenv("AUTOFIRMA_BATCH_BREAKER_THRESHOLD", "99")
	if got := resolveBatchRemoteBreakerThreshold(); got != 10 {
		t.Fatalf("threshold debe caparse a 10, obtenido: %d", got)
	}
}

func TestResolveBatchRemoteBreakerCooldownDefault(t *testing.T) {
	t.Setenv("AUTOFIRMA_BATCH_BREAKER_COOLDOWN_MS", "")
	t.Setenv("AUTOFIRMA_BATCH_BREAKER_COOLDOWN_SEC", "")
	if got := resolveBatchRemoteBreakerCooldown(); got != 20*time.Second {
		t.Fatalf("cooldown default inesperado: %v", got)
	}
}

func TestResolveBatchRemoteBreakerCooldownFromMS(t *testing.T) {
	t.Setenv("AUTOFIRMA_BATCH_BREAKER_COOLDOWN_MS", "4500")
	t.Setenv("AUTOFIRMA_BATCH_BREAKER_COOLDOWN_SEC", "")
	if got := resolveBatchRemoteBreakerCooldown(); got != 4500*time.Millisecond {
		t.Fatalf("cooldown ms inesperado: %v", got)
	}
}

func TestResolveBatchRemoteBreakerCooldownFromSec(t *testing.T) {
	t.Setenv("AUTOFIRMA_BATCH_BREAKER_COOLDOWN_MS", "")
	t.Setenv("AUTOFIRMA_BATCH_BREAKER_COOLDOWN_SEC", "12")
	if got := resolveBatchRemoteBreakerCooldown(); got != 12*time.Second {
		t.Fatalf("cooldown sec inesperado: %v", got)
	}
}

func TestResolveBatchRemoteBreakerCooldownCapped(t *testing.T) {
	t.Setenv("AUTOFIRMA_BATCH_BREAKER_COOLDOWN_MS", "9999999")
	t.Setenv("AUTOFIRMA_BATCH_BREAKER_COOLDOWN_SEC", "")
	if got := resolveBatchRemoteBreakerCooldown(); got != 5*time.Minute {
		t.Fatalf("cooldown debe caparse a 5m, obtenido: %v", got)
	}
}
