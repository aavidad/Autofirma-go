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
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	batchResultDone    = "DONE_AND_SAVED"
	batchResultSkipped = "SKIPPED"
	batchResultError   = "ERROR_PRE"

	batchOperationSign        = "sign"
	batchOperationCoSign      = "cosign"
	batchOperationCounterSign = "countersign"
)

var batchHTTPPostFunc = func(rawURL string) ([]byte, error) {
	resp, err := http.Post(rawURL, "application/x-www-form-urlencoded", nil) // #nosec G107 -- URL viene de integración batch Java compatible.
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return nil, readErr
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &batchHTTPError{
			StatusCode: resp.StatusCode,
			Body:       truncateBatchBodyForError(body),
		}
	}
	return body, nil
}

type batchHTTPError struct {
	StatusCode int
	Body       string
}

func (e *batchHTTPError) Error() string {
	if e == nil {
		return "http error"
	}
	if strings.TrimSpace(e.Body) == "" {
		return fmt.Sprintf("http status %d", e.StatusCode)
	}
	return fmt.Sprintf("http status %d: %s", e.StatusCode, e.Body)
}

type batchRequest struct {
	StopOnError bool               `json:"stoponerror"`
	SubOp       string             `json:"suboperation"`
	Format      string             `json:"format"`
	Algorithm   string             `json:"algorithm"`
	ExtraParams string             `json:"extraparams"`
	SingleSigns []batchSingleEntry `json:"singlesigns"`
}

type batchSingleEntry struct {
	ID          string `json:"id"`
	SubOp       string `json:"suboperation"`
	DataRef     string `json:"datareference"`
	Format      string `json:"format"`
	Algorithm   string `json:"algorithm"`
	ExtraParams string `json:"extraparams"`
}

type batchResponse struct {
	Signs []batchSingleResult `json:"signs"`
}

type batchSingleResult struct {
	ID          string `json:"id"`
	Result      string `json:"result"`
	Description string `json:"description,omitempty"`
	Signature   string `json:"signature,omitempty"`
}

type xmlBatchRequest struct {
	XMLName     xml.Name         `xml:"signbatch"`
	StopOnError string           `xml:"stoponerror,attr"`
	Algorithm   string           `xml:"algorithm,attr"`
	SubOp       string           `xml:"suboperation,attr"`
	SingleSigns []xmlBatchSingle `xml:"singlesign"`
}

type xmlBatchSingle struct {
	ID          string `xml:"Id,attr"`
	DataSource  string `xml:"datasource"`
	Format      string `xml:"format"`
	SubOp       string `xml:"suboperation"`
	ExtraParams string `xml:"extraparams"`
}

type xmlBatchResponse struct {
	XMLName xml.Name           `xml:"signs"`
	Signs   []xmlSignResultLog `xml:"signresult"`
}

type xmlSignResultLog struct {
	ID          string `xml:"id,attr"`
	Result      string `xml:"result,attr"`
	Description string `xml:"description,attr"`
}

type batchPreResponse struct {
	TD      *triphaseDataResponse `json:"td"`
	Results []batchSingleResult   `json:"results"`
}

type triphaseDataResponse struct {
	Format   string                `json:"format"`
	SignInfo []triphaseSignInfoDTO `json:"signinfo"`
}

type triphaseSignInfoDTO struct {
	ID     string            `json:"id"`
	SignID string            `json:"signid,omitempty"`
	Params map[string]string `json:"params"`
}

type triphaseDataRequest struct {
	Format   string                `json:"format,omitempty"`
	SignInfo []triphaseSignInfoDTO `json:"signinfo"`
}

type xmlTriphaseData struct {
	XMLName xml.Name          `xml:"xml"`
	Firmas  xmlTriphaseFirmas `xml:"firmas"`
}

type xmlTriphaseFirmas struct {
	Format string             `xml:"format,attr,omitempty"`
	Firmas []xmlTriphaseFirma `xml:"firma"`
}

type xmlTriphaseFirma struct {
	ID     string             `xml:"Id,attr,omitempty"`
	SignID string             `xml:"signid,attr,omitempty"`
	Params []xmlTriphaseParam `xml:"param"`
}

type xmlTriphaseParam struct {
	Name  string `xml:"n,attr"`
	Value string `xml:",chardata"`
}

func (s *WebSocketServer) processBatchRequest(state *ProtocolState) string {
	isJSONBatch := parseBoolParam(state.Params.Get("jsonbatch"), state.Params.Get("jsonBatch"))
	isLocalBatch := parseBoolParam(state.Params.Get("localBatchProcess"), state.Params.Get("localbatchprocess"))
	preURL := strings.TrimSpace(state.Params.Get("batchpresignerurl"))
	postURL := strings.TrimSpace(state.Params.Get("batchpostsignerurl"))
	if !isLocalBatch && !isJSONBatch && (preURL == "" || postURL == "") {
		return s.formatError("ERROR_UNSUPPORTED_OPERATION", "Lote trifasico XML no soportado")
	}

	rawBatch, err := extractBatchPayload(state)
	if err != nil {
		return s.formatError("ERROR_DOWNLOAD", err.Error())
	}
	req, err := parseBatchRequest(rawBatch, isJSONBatch)
	if err != nil {
		if isJSONBatch {
			return s.formatError("ERROR_PARSING_URI", "Lote JSON invalido")
		}
		return s.formatError("ERROR_PARSING_URI", "Lote XML invalido")
	}
	if len(req.SingleSigns) == 0 {
		return s.formatError("ERROR_PARSING_URI", "Lote sin operaciones")
	}

	cert, certErr := s.selectBatchSigningCertificate(state)
	if certErr != "" {
		return certErr
	}

	var respBytes []byte
	if isLocalBatch {
		globalExtra := decodeBatchExtraParams(req.ExtraParams)
		results := make([]batchSingleResult, 0, len(req.SingleSigns))
		errorOcurred := false

		for _, item := range req.SingleSigns {
			id := strings.TrimSpace(item.ID)
			if id == "" {
				id = "unknown"
			}
			if errorOcurred && req.StopOnError {
				results = append(results, batchSingleResult{ID: id, Result: batchResultSkipped})
				continue
			}

			res := s.executeBatchSingle(item, req, cert.ID, globalExtra)
			if res.Result == batchResultError {
				errorOcurred = true
				if req.StopOnError {
					for i := range results {
						results[i].Result = batchResultSkipped
						results[i].Signature = ""
					}
				}
			}
			results = append(results, res)
		}
		respBytes, err = serializeBatchResponse(results, isJSONBatch)
		if err != nil {
			return "SAF_12: Error preparando respuesta de lote"
		}
	} else {
		respText, err := s.executeRemoteTriphaseBatch(state, rawBatch, cert, isJSONBatch)
		if err != nil {
			return err.Error()
		}
		respBytes = []byte(respText)
	}

	needCert := parseBoolParam(state.Params.Get("needcert"), state.Params.Get("needCert"))
	if strings.TrimSpace(state.Key) != "" {
		encBatch, e := AutoFirmaEncryptAndFormat(respBytes, []byte(state.Key))
		if e != nil {
			return "SAF_12: Error preparando respuesta de lote"
		}
		if !needCert {
			return encBatch
		}
		encCert, e := AutoFirmaEncryptAndFormat(cert.Content, []byte(state.Key))
		if e != nil {
			return "SAF_12: Error preparando respuesta de lote"
		}
		return encBatch + "|" + encCert
	}

	plain := base64.StdEncoding.EncodeToString(respBytes)
	if !needCert {
		return plain
	}
	return plain + "|" + base64.StdEncoding.EncodeToString(cert.Content)
}

func extractBatchPayload(state *ProtocolState) ([]byte, error) {
	if state == nil {
		return nil, fmt.Errorf("estado de protocolo nulo")
	}
	if dat := strings.TrimSpace(state.Params.Get("dat")); dat != "" {
		if decoded, err := decodeAutoFirmaB64(strings.ReplaceAll(dat, " ", "+")); err == nil {
			return decoded, nil
		}
		return []byte(dat), nil
	}

	path, err := state.DownloadFile()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("lote sin datos")
	}
	return os.ReadFile(path)
}

func parseBatchRequest(raw []byte, isJSON bool) (*batchRequest, error) {
	if isJSON {
		return parseBatchJSONRequest(raw)
	}
	return parseBatchXMLRequest(raw)
}

func parseBatchJSONRequest(raw []byte) (*batchRequest, error) {
	var req batchRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

func parseBatchXMLRequest(raw []byte) (*batchRequest, error) {
	var xmlReq xmlBatchRequest
	if err := xml.Unmarshal(raw, &xmlReq); err != nil {
		return nil, err
	}
	req := &batchRequest{
		StopOnError: strings.EqualFold(strings.TrimSpace(xmlReq.StopOnError), "true"),
		Algorithm:   strings.TrimSpace(xmlReq.Algorithm),
		SubOp:       strings.TrimSpace(xmlReq.SubOp),
		SingleSigns: make([]batchSingleEntry, 0, len(xmlReq.SingleSigns)),
	}
	for _, s := range xmlReq.SingleSigns {
		req.SingleSigns = append(req.SingleSigns, batchSingleEntry{
			ID:          strings.TrimSpace(s.ID),
			SubOp:       strings.TrimSpace(s.SubOp),
			DataRef:     strings.TrimSpace(s.DataSource),
			Format:      strings.TrimSpace(s.Format),
			Algorithm:   strings.TrimSpace(xmlReq.Algorithm),
			ExtraParams: strings.TrimSpace(s.ExtraParams),
		})
	}
	return req, nil
}

func serializeBatchResponse(results []batchSingleResult, isJSON bool) ([]byte, error) {
	if isJSON {
		return json.Marshal(batchResponse{Signs: results})
	}
	xmlResp := xmlBatchResponse{
		Signs: make([]xmlSignResultLog, 0, len(results)),
	}
	for _, r := range results {
		xmlResp.Signs = append(xmlResp.Signs, xmlSignResultLog{
			ID:          strings.TrimSpace(r.ID),
			Result:      strings.TrimSpace(r.Result),
			Description: strings.TrimSpace(r.Description),
		})
	}
	out, err := xml.Marshal(xmlResp)
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), out...), nil
}

func (s *WebSocketServer) executeRemoteTriphaseBatch(state *ProtocolState, rawBatch []byte, cert protocol.Certificate, isJSONBatch bool) (string, error) {
	preURL := strings.TrimSpace(state.Params.Get("batchpresignerurl"))
	postURL := strings.TrimSpace(state.Params.Get("batchpostsignerurl"))
	if preURL == "" || postURL == "" {
		return "", fmt.Errorf("SAF_03: Faltan URLs de prefirma/postfirma de lote")
	}

	batchB64URL := base64.URLEncoding.EncodeToString(rawBatch)
	certB64 := base64.URLEncoding.EncodeToString(cert.Content)
	batchParam := "xml"
	if isJSONBatch {
		batchParam = "json"
	}
	preReq := preURL + "?" + batchParam + "=" + url.QueryEscape(batchB64URL) + "&certs=" + url.QueryEscape(certB64)
	preRaw, err := batchHTTPPostFunc(preReq)
	if err != nil {
		return "", fmt.Errorf("%s", mapBatchRemoteHTTPError("prefirma", err))
	}
	if protoErr := detectBatchServiceProtocolError(preRaw, "prefirma"); protoErr != nil {
		return "", protoErr
	}

	var tdSignedB64 string
	batchForPost := rawBatch
	if isJSONBatch {
		var preResp batchPreResponse
		if err := json.Unmarshal(preRaw, &preResp); err != nil {
			return "", fmt.Errorf("SAF_27: Respuesta de prefirma de lote invalida")
		}
		if preResp.TD == nil && len(preResp.Results) == 0 {
			return `{"signs":[]}`, nil
		}
		if preResp.TD == nil {
			out, mErr := json.Marshal(batchResponse{Signs: preResp.Results})
			if mErr != nil {
				return "", fmt.Errorf("SAF_12: Error preparando respuesta de lote")
			}
			return string(out), nil
		}

		tdSigned, err := signTriphaseData(preResp.TD, cert.ID, extractBatchAlgorithm(rawBatch))
		if err != nil {
			return "", fmt.Errorf("SAF_27: Error en firma trifasica de lote")
		}
		tdJSON, err := json.Marshal(tdSigned)
		if err != nil {
			return "", fmt.Errorf("SAF_27: Error en firma trifasica de lote")
		}
		tdSignedB64 = base64.URLEncoding.EncodeToString(tdJSON)

		if len(preResp.Results) > 0 {
			if updated, uErr := mergePresignResultsIntoBatchJSON(rawBatch, preResp.Results); uErr == nil {
				batchForPost = updated
			}
		}
	} else {
		tdSignedXML, err := signTriphaseDataXML(preRaw, cert.ID, extractBatchAlgorithmFromXML(rawBatch))
		if err != nil {
			return "", fmt.Errorf("SAF_27: Error en firma trifasica de lote")
		}
		tdSignedB64 = base64.URLEncoding.EncodeToString(tdSignedXML)
	}

	postReq := postURL + "?" + batchParam + "=" + url.QueryEscape(base64.URLEncoding.EncodeToString(batchForPost)) +
		"&certs=" + url.QueryEscape(certB64) +
		"&tridata=" + url.QueryEscape(tdSignedB64)
	postRaw, err := batchHTTPPostFunc(postReq)
	if err != nil {
		return "", fmt.Errorf("%s", mapBatchRemoteHTTPError("postfirma", err))
	}
	if protoErr := detectBatchServiceProtocolError(postRaw, "postfirma"); protoErr != nil {
		return "", protoErr
	}
	return string(postRaw), nil
}

func truncateBatchBodyForError(body []byte) string {
	s := strings.TrimSpace(string(body))
	if len(s) <= 180 {
		return s
	}
	return s[:180]
}

func mapBatchRemoteHTTPError(phase string, err error) string {
	var httpErr *batchHTTPError
	if errors.As(err, &httpErr) && httpErr != nil {
		if httpErr.StatusCode == http.StatusBadRequest {
			return "SAF_03: Parametros invalidos en servicio de " + phase + " de lote"
		}
		if httpErr.StatusCode >= 400 && httpErr.StatusCode < 500 {
			return "SAF_26: Error contactando servicio de " + phase + " de lote"
		}
		return "SAF_27: Error en servicio de " + phase + " de lote"
	}
	return "SAF_26: Error contactando servicio de " + phase + " de lote"
}

func detectBatchServiceProtocolError(raw []byte, phase string) error {
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return nil
	}
	up := strings.ToUpper(text)
	if strings.HasPrefix(up, "SAF_") {
		return fmt.Errorf("%s", text)
	}
	if strings.HasPrefix(up, "ERR-") {
		return fmt.Errorf("SAF_27: Error en servicio de %s de lote", phase)
	}
	return nil
}

func extractBatchAlgorithm(rawBatch []byte) string {
	var req batchRequest
	if err := json.Unmarshal(rawBatch, &req); err != nil {
		return "SHA256withRSA"
	}
	if strings.TrimSpace(req.Algorithm) == "" {
		return "SHA256withRSA"
	}
	return strings.TrimSpace(req.Algorithm)
}

func signTriphaseData(td *triphaseDataResponse, certID, algorithm string) (*triphaseDataRequest, error) {
	if td == nil {
		return nil, fmt.Errorf("nil")
	}
	out := &triphaseDataRequest{
		Format:   strings.TrimSpace(td.Format),
		SignInfo: make([]triphaseSignInfoDTO, 0, len(td.SignInfo)),
	}
	for _, si := range td.SignInfo {
		params := make(map[string]string, len(si.Params)+1)
		for k, v := range si.Params {
			params[k] = v
		}
		preB64 := strings.TrimSpace(params["PRE"])
		if preB64 == "" {
			return nil, fmt.Errorf("missing PRE")
		}
		preData, err := decodeAutoFirmaB64(strings.ReplaceAll(preB64, " ", "+"))
		if err != nil {
			return nil, err
		}
		pk1B64, err := signPKCS1Func(preData, certID, algorithm)
		if err != nil {
			log.Printf("[Batch] PKCS1 signing failed id=%s err=%v", si.ID, err)
			return nil, err
		}
		params["PK1"] = pk1B64
		out.SignInfo = append(out.SignInfo, triphaseSignInfoDTO{
			ID:     si.ID,
			SignID: si.SignID,
			Params: params,
		})
	}
	return out, nil
}

func signTriphaseDataXML(rawTD []byte, certID, algorithm string) ([]byte, error) {
	var td xmlTriphaseData
	if err := xml.Unmarshal(rawTD, &td); err != nil {
		return nil, err
	}
	for i := range td.Firmas.Firmas {
		preB64 := ""
		for j := range td.Firmas.Firmas[i].Params {
			if strings.EqualFold(td.Firmas.Firmas[i].Params[j].Name, "PRE") {
				preB64 = strings.TrimSpace(td.Firmas.Firmas[i].Params[j].Value)
				break
			}
		}
		if preB64 == "" {
			return nil, fmt.Errorf("missing PRE")
		}
		preData, err := decodeAutoFirmaB64(strings.ReplaceAll(preB64, " ", "+"))
		if err != nil {
			return nil, err
		}
		pk1B64, err := signPKCS1Func(preData, certID, algorithm)
		if err != nil {
			return nil, err
		}
		td.Firmas.Firmas[i].Params = append(td.Firmas.Firmas[i].Params, xmlTriphaseParam{
			Name:  "PK1",
			Value: pk1B64,
		})
	}
	out, err := xml.Marshal(td)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func extractBatchAlgorithmFromXML(rawBatch []byte) string {
	var xmlReq xmlBatchRequest
	if err := xml.Unmarshal(rawBatch, &xmlReq); err != nil {
		return "SHA256withRSA"
	}
	if strings.TrimSpace(xmlReq.Algorithm) == "" {
		return "SHA256withRSA"
	}
	return strings.TrimSpace(xmlReq.Algorithm)
}

func mergePresignResultsIntoBatchJSON(rawBatch []byte, results []batchSingleResult) ([]byte, error) {
	var root map[string]interface{}
	if err := json.Unmarshal(rawBatch, &root); err != nil {
		return nil, err
	}
	ss, ok := root["singlesigns"].([]interface{})
	if !ok {
		return rawBatch, nil
	}
	byID := map[string]batchSingleResult{}
	for _, r := range results {
		byID[strings.TrimSpace(r.ID)] = r
	}
	for i := range ss {
		m, ok := ss[i].(map[string]interface{})
		if !ok {
			continue
		}
		id, _ := m["id"].(string)
		res, found := byID[strings.TrimSpace(id)]
		if !found {
			continue
		}
		delete(m, "datareference")
		delete(m, "format")
		delete(m, "suboperation")
		delete(m, "extraparams")
		m["result"] = res.Result
		if strings.TrimSpace(res.Description) != "" {
			m["description"] = res.Description
		}
	}
	return json.Marshal(root)
}

func (s *WebSocketServer) selectBatchSigningCertificate(state *ProtocolState) (protocol.Certificate, string) {
	certs, err := getSystemCertificatesFunc()
	if err != nil {
		return protocol.Certificate{}, "SAF_08: Error accediendo al almacen de certificados"
	}
	if len(certs) == 0 {
		return protocol.Certificate{}, "SAF_19: No hay certificados disponibles"
	}

	resetSticky := parseBoolParam(state.Params.Get("resetsticky"), state.Params.Get("resetSticky"))
	sticky := parseBoolParam(state.Params.Get("sticky"))
	if resetSticky {
		s.stickyID = ""
	}
	if sticky && s.stickyID != "" {
		if idx := findCertificateIndexByID(certs, s.stickyID); idx >= 0 {
			return certs[idx], ""
		}
	}
	if s.ui == nil {
		return protocol.Certificate{}, "SAF_09: Interfaz de firma no disponible"
	}

	filtered, _ := applySelectCertFilters(certs, state)
	if len(filtered) == 0 {
		filtered = certs
	}
	idx := findPreferredCertificateIndex(filtered)
	if idx < 0 {
		return protocol.Certificate{}, "SAF_19: No hay certificados disponibles"
	}

	chosen, canceled, selErr := selectCertDialogFunc(filtered)
	if canceled {
		return protocol.Certificate{}, "CANCEL"
	}
	if selErr != nil {
		return protocol.Certificate{}, "SAF_08: Error accediendo al almacen de certificados"
	}
	if chosen >= 0 && chosen < len(filtered) {
		idx = chosen
	}

	if sticky {
		s.stickyID = filtered[idx].ID
	}
	return filtered[idx], ""
}

func decodeBatchExtraParams(v string) map[string]string {
	props := decodeProtocolProperties(strings.TrimSpace(v))
	if len(props) > 0 {
		return props
	}
	if strings.TrimSpace(v) == "" {
		return map[string]string{}
	}
	return parseProperties(strings.ReplaceAll(strings.TrimSpace(v), `\n`, "\n"))
}

func (s *WebSocketServer) executeBatchSingle(item batchSingleEntry, req *batchRequest, certID string, globalExtra map[string]string) batchSingleResult {
	result := batchSingleResult{
		ID:     strings.TrimSpace(item.ID),
		Result: batchResultDone,
	}
	if result.ID == "" {
		result.ID = "unknown"
	}

	format := strings.TrimSpace(item.Format)
	if format == "" {
		format = strings.TrimSpace(req.Format)
	}
	format = normalizeProtocolFormat(format)
	if format == "" {
		format = "cades"
	}

	algorithm := strings.TrimSpace(item.Algorithm)
	if algorithm == "" {
		algorithm = strings.TrimSpace(req.Algorithm)
	}
	operation, opErr := resolveBatchOperation(item.SubOp, req.SubOp)
	if opErr != nil {
		result.Result = batchResultError
		result.Description = opErr.Error()
		return result
	}

	dataBytes, err := resolveBatchDataReference(strings.TrimSpace(item.DataRef))
	if err != nil {
		result.Result = batchResultError
		result.Description = "Datos de lote invalidos"
		return result
	}

	opts := map[string]interface{}{}
	for k, v := range globalExtra {
		applyProtocolSignOption(opts, k, v)
	}
	for k, v := range decodeBatchExtraParams(item.ExtraParams) {
		applyProtocolSignOption(opts, k, v)
	}
	if strings.TrimSpace(algorithm) != "" {
		opts["algorithm"] = algorithm
	}
	expandProtocolPolicyOptions(opts, format)

	dataB64 := base64.StdEncoding.EncodeToString(dataBytes)
	signFunc := signDataFunc
	switch operation {
	case batchOperationCoSign:
		signFunc = coSignDataFunc
	case batchOperationCounterSign:
		signFunc = counterSignDataFunc
	}
	sigB64, signErr := signFunc(dataB64, certID, "", format, opts)
	if signErr != nil {
		result.Result = batchResultError
		result.Description = signErr.Error()
		return result
	}
	result.Signature = sigB64
	return result
}

func resolveBatchOperation(singleOp, globalOp string) (string, error) {
	op := strings.TrimSpace(singleOp)
	if op == "" {
		op = strings.TrimSpace(globalOp)
	}
	if op == "" {
		return batchOperationSign, nil
	}
	switch strings.ToLower(op) {
	case "sign", "firmar":
		return batchOperationSign, nil
	case "cosign", "cofirmar":
		return batchOperationCoSign, nil
	case "countersign", "contrafirmar", "contrafirmar_arbol", "contrafirmar_hojas":
		return batchOperationCounterSign, nil
	default:
		return "", fmt.Errorf("Operacion de lote no soportada")
	}
}

func resolveBatchDataReference(ref string) ([]byte, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, fmt.Errorf("empty")
	}
	if decoded, err := decodeAutoFirmaB64(strings.ReplaceAll(ref, " ", "+")); err == nil {
		return decoded, nil
	}

	u, err := url.Parse(ref)
	if err == nil && strings.TrimSpace(u.Scheme) != "" {
		switch strings.ToLower(strings.TrimSpace(u.Scheme)) {
		case "http", "https":
			resp, err := http.Get(ref) // #nosec G107 -- compatibilidad con datasource remoto del protocolo batch.
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode > 299 {
				return nil, fmt.Errorf("http status %d", resp.StatusCode)
			}
			return io.ReadAll(resp.Body)
		case "file":
			return os.ReadFile(u.Path)
		}
	}

	if strings.HasPrefix(ref, "/") || strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "../") {
		return os.ReadFile(ref)
	}
	return nil, fmt.Errorf("unsupported datareference")
}
