// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"autofirma-host/pkg/protocol"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	batchResultDone    = "DONE_AND_SAVED"
	batchResultSkipped = "SKIPPED"
	batchResultError   = "ERROR_PRE"

	batchOperationSign        = "sign"
	batchOperationCoSign      = "cosign"
	batchOperationCounterSign = "countersign"

	batchRemoteDefaultMaxAttempts  = 3
	batchRemoteMaxAttemptsCap      = 6
	batchRemoteBreakerThreshold    = 3
	batchRemoteBreakerCooldown     = 20 * time.Second
	batchRemoteBreakerThresholdCap = 10
	batchRemoteBreakerCooldownCap  = 5 * time.Minute
)

type batchRemoteBreakerState struct {
	failures  int
	openUntil time.Time
}

var (
	batchRemoteBreakerMu sync.Mutex
	batchRemoteBreaker   = map[string]batchRemoteBreakerState{}
)

var batchHTTPPostFunc = func(rawURL string) ([]byte, error) {
	timeout := resolveBatchHTTPTimeout()
	client := &http.Client{Timeout: timeout}
	body, err := batchHTTPPostOnce(client, rawURL)
	if err == nil {
		return body, nil
	}
	if isTLSUnknownAuthorityError(err) {
		fallbackClient, loaded, fbErr := buildBatchHTTPFallbackClient(timeout, rawURL)
		if fbErr == nil && loaded > 0 {
			log.Printf("[Batch] fallback TLS activado (unknown authority): certificados extra cargados=%d", loaded)
			body2, err2 := batchHTTPPostOnce(fallbackClient, rawURL)
			if err2 == nil {
				return body2, nil
			}
			err = err2
		} else if fbErr != nil {
			log.Printf("[Batch] fallback TLS no disponible: %v", fbErr)
		}
		if host, allowed := shouldUseBatchInsecureTLSException(rawURL); allowed {
			log.Printf("[Batch] AVISO SEGURIDAD: usando excepción TLS por dominio=%s (cadena no verificada).", host)
			insecureClient := buildBatchHTTPInsecureExceptionClient(timeout, host)
			body3, err3 := batchHTTPPostOnce(insecureClient, rawURL)
			if err3 == nil {
				return body3, nil
			}
			err = err3
		}
	}
	safeMsg := strings.ReplaceAll(strings.TrimSpace(err.Error()), rawURL, sanitizeBatchRemoteURL(rawURL))
	return nil, &batchTransportError{Detail: safeMsg, Cause: err}
}

func batchHTTPPostOnce(client *http.Client, rawURL string) ([]byte, error) {
	respBody, err := batchHTTPPostOnceMode(client, rawURL, false)
	if err != nil {
		var httpErr *batchHTTPError
		if errors.As(err, &httpErr) && httpErr != nil && shouldFallbackToFormBody(httpErr) {
			log.Printf("[Batch] fallback de transporte remoto: reintento POST form-body (estado=%d)", httpErr.StatusCode)
			return batchHTTPPostOnceMode(client, rawURL, true)
		}
		return nil, err
	}
	return respBody, nil
}

func batchHTTPPostOnceMode(client *http.Client, rawURL string, sendQueryAsFormBody bool) ([]byte, error) {
	targetURL := strings.TrimSpace(rawURL)
	formBody := ""
	originalQuery := ""
	if u, pErr := url.Parse(targetURL); pErr == nil && u != nil {
		originalQuery = strings.TrimSpace(u.RawQuery)
	}
	if sendQueryAsFormBody {
		if u, pErr := url.Parse(targetURL); pErr == nil && u != nil {
			formBody = strings.TrimSpace(u.RawQuery)
			u.RawQuery = ""
			targetURL = u.String()
		}
	}
	var reqBody io.Reader
	if sendQueryAsFormBody && formBody != "" {
		reqBody = strings.NewReader(formBody)
	}
	req, err := http.NewRequest(http.MethodPost, targetURL, reqBody) // #nosec G107 -- URL viene de integración batch Java compatible.
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AutoFirma/1.6.5")
	if sendQueryAsFormBody && formBody != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	}
	if isBatchCompatTraceEnabled() {
		log.Printf(
			"[Batch-TRACE] envio remoto modo=%s destino=%s ctype=%q query=%s body=%s",
			batchTransportModeLabel(sendQueryAsFormBody, formBody),
			sanitizeBatchRemoteURL(targetURL),
			strings.TrimSpace(req.Header.Get("Content-Type")),
			batchPayloadFingerprint(originalQuery),
			batchPayloadFingerprint(formBody),
		)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return nil, readErr
	}
	if isBatchCompatTraceEnabled() {
		log.Printf(
			"[Batch-TRACE] respuesta remota estado=%d destino=%s body=%s",
			resp.StatusCode,
			sanitizeBatchRemoteURL(targetURL),
			batchPayloadFingerprint(string(respBody)),
		)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &batchHTTPError{
			StatusCode: resp.StatusCode,
			Body:       truncateBatchBodyForError(respBody),
		}
	}
	return respBody, nil
}

func shouldFallbackToFormBody(httpErr *batchHTTPError) bool {
	if httpErr == nil || httpErr.StatusCode != http.StatusBadRequest {
		return false
	}
	body := strings.ToLower(strings.TrimSpace(httpErr.Body))
	if body == "" {
		return false
	}
	return strings.Contains(body, "parametro json") ||
		strings.Contains(body, "parametro xml") ||
		strings.Contains(body, "definicion de lote")
}

func isTLSUnknownAuthorityError(err error) bool {
	if err == nil {
		return false
	}
	var unknownAuthorityErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthorityErr) {
		return true
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	return strings.Contains(msg, "unknown authority") || strings.Contains(msg, "certificate signed by unknown authority")
}

func buildBatchHTTPFallbackClient(timeout time.Duration, rawURL string) (*http.Client, int, error) {
	roots, _ := x509.SystemCertPool()
	if roots == nil {
		roots = x509.NewCertPool()
	}
	loaded := 0
	loaded += appendEndpointTrustStoreCerts(roots)
	loaded += appendBatchRemoteChainCerts(roots, rawURL)
	loaded += appendBatchFallbackFNMTCerts(roots)
	if loaded == 0 {
		return nil, 0, fmt.Errorf("no se encontraron certificados de fallback (almacén local/FNMT/cadena remota)")
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
		},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}, loaded, nil
}

func appendBatchRemoteChainCerts(pool *x509.CertPool, rawURL string) int {
	if pool == nil {
		return 0
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u == nil || strings.TrimSpace(u.Hostname()) == "" {
		return 0
	}
	host := strings.TrimSpace(u.Hostname())
	port := strings.TrimSpace(u.Port())
	if port == "" {
		port = "443"
	}
	target := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // Solo para extraer cadena y revalidar con RootCAs en el siguiente intento.
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return 0
	}
	defer conn.Close()

	cs := conn.ConnectionState()
	loaded := 0
	for _, cert := range cs.PeerCertificates {
		if cert == nil || len(cert.Raw) == 0 {
			continue
		}
		block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
		if pool.AppendCertsFromPEM(pem.EncodeToMemory(block)) {
			loaded++
		}
	}
	return loaded
}

func appendBatchFallbackFNMTCerts(pool *x509.CertPool) int {
	if pool == nil {
		return 0
	}
	paths := candidateBatchFNMTCertPaths()
	seen := map[string]bool{}
	loaded := 0
	for _, p := range paths {
		pp := strings.TrimSpace(p)
		if pp == "" || seen[pp] {
			continue
		}
		seen[pp] = true
		data, err := os.ReadFile(pp)
		if err != nil || len(data) == 0 {
			continue
		}
		if pool.AppendCertsFromPEM(data) {
			loaded++
		}
	}
	return loaded
}

func candidateBatchFNMTCertPaths() []string {
	paths := []string{
		"/opt/autofirma-dipgra/certs/fnmt-accomp.crt",
		"/usr/local/share/ca-certificates/fnmt-accomp.crt",
		"/usr/share/ca-certificates/AutoFirma/fnmt-accomp.crt",
	}
	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		paths = append(paths,
			filepath.Join(exeDir, "certs", "fnmt-accomp.crt"),
			filepath.Join(exeDir, "fnmt-accomp.crt"),
			filepath.Join(exeDir, "ACCOMP.crt"),
		)
	}
	if wd, err := os.Getwd(); err == nil {
		paths = append(paths,
			filepath.Join(wd, "packaging", "linux", "certs", "fnmt-accomp.crt"),
			filepath.Join(wd, "packaging", "macos", "certs", "fnmt-accomp.crt"),
			filepath.Join(wd, "packaging", "windows", "certs", "fnmt-accomp.crt"),
			filepath.Join(wd, "ACCOMP.crt"),
		)
	}
	return paths
}

func shouldUseBatchInsecureTLSException(rawURL string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u == nil {
		return "", false
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "" {
		return "", false
	}
	raw := strings.TrimSpace(os.Getenv("AUTOFIRMA_BATCH_TLS_INSECURE_DOMAINS"))
	if raw == "" {
		return host, false
	}
	for _, token := range strings.Split(raw, ",") {
		domain := strings.ToLower(strings.TrimSpace(token))
		if domain == "" {
			continue
		}
		if host == domain {
			return host, true
		}
		if strings.HasPrefix(domain, "*.") {
			suffix := strings.TrimPrefix(domain, "*")
			if strings.HasSuffix(host, suffix) {
				return host, true
			}
		}
	}
	return host, false
}

func buildBatchHTTPInsecureExceptionClient(timeout time.Duration, expectedHost string) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, // Excepción explícita por dominio. Se valida hostname manualmente en VerifyConnection.
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return fmt.Errorf("sin certificado presentado por el servidor")
				}
				return cs.PeerCertificates[0].VerifyHostname(expectedHost)
			},
		},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}
}

func resolveBatchHTTPTimeout() time.Duration {
	// Default conservative timeout for remote pre/post batch services.
	const defaultTimeout = 15 * time.Second

	if msRaw := strings.TrimSpace(os.Getenv("AUTOFIRMA_BATCH_HTTP_TIMEOUT_MS")); msRaw != "" {
		if ms, err := strconv.Atoi(msRaw); err == nil && ms > 0 {
			return time.Duration(ms) * time.Millisecond
		}
	}
	if secRaw := strings.TrimSpace(os.Getenv("AUTOFIRMA_BATCH_HTTP_TIMEOUT_SEC")); secRaw != "" {
		if sec, err := strconv.Atoi(secRaw); err == nil && sec > 0 {
			return time.Duration(sec) * time.Second
		}
	}
	return defaultTimeout
}

type batchHTTPError struct {
	StatusCode int
	Body       string
}

type batchCircuitOpenError struct {
	Key       string
	OpenUntil time.Time
}

type batchTransportError struct {
	Detail string
	Cause  error
}

func (e *batchHTTPError) Error() string {
	if e == nil {
		return "error http"
	}
	if strings.TrimSpace(e.Body) == "" {
		return fmt.Sprintf("http status %d", e.StatusCode)
	}
	return fmt.Sprintf("http status %d: %s", e.StatusCode, e.Body)
}

func (e *batchCircuitOpenError) Error() string {
	if e == nil {
		return "circuit open"
	}
	return fmt.Sprintf("circuit open for %s until %s", e.Key, e.OpenUntil.Format(time.RFC3339))
}

func (e *batchTransportError) Error() string {
	if e == nil {
		return "error de transporte"
	}
	if strings.TrimSpace(e.Detail) != "" {
		return e.Detail
	}
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return "error de transporte"
}

func (e *batchTransportError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

type batchRequest struct {
	StopOnError bool               `json:"stoponerror"`
	SubOp       string             `json:"suboperation"`
	Format      string             `json:"format"`
	Algorithm   string             `json:"algorithm"`
	ExtraParams string             `json:"extraparams"`
	SingleSigns []batchSingleEntry `json:"singlesigns"`
}

type batchRequestJSONCompat struct {
	StopOnError bool                     `json:"stopOnError"`
	SubOp       string                   `json:"subOperation"`
	Format      string                   `json:"format"`
	Algorithm   string                   `json:"algorithm"`
	ExtraParams string                   `json:"extraParams"`
	SingleSigns []batchSingleEntryCompat `json:"singleSigns"`
}

type batchSingleEntryCompat struct {
	ID          string `json:"id"`
	SubOp       string `json:"subOperation"`
	DataRef     string `json:"dataReference"`
	Format      string `json:"format"`
	Algorithm   string `json:"algorithm"`
	ExtraParams string `json:"extraParams"`
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
	ExtraParams string           `xml:"extraparams"`
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
	Signs    []triphaseSignBlock   `json:"signs,omitempty"`
}

type triphaseSignBlock struct {
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
	isJSONBatch := parseBoolParam(
		getQueryParam(state.Params, "jsonbatch", "jsonBatch"),
	)
	isLocalBatch := parseBoolParam(
		getQueryParam(state.Params, "localBatchProcess", "localbatchprocess"),
	)
	preURL := strings.TrimSpace(getQueryParam(
		state.Params,
		"batchpresignerurl",
		"batchPreSignerUrl",
		"batchPreSignerURL",
	))
	postURL := strings.TrimSpace(getQueryParam(
		state.Params,
		"batchpostsignerurl",
		"batchPostSignerUrl",
		"batchPostSignerURL",
	))
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

			res := s.executeBatchSingle(state, item, req, cert.ID, globalExtra)
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
		respText, err := s.executeRemoteTriphaseBatch(state, rawBatch, req, cert, isJSONBatch)
		if err != nil {
			return err.Error()
		}
		respBytes = []byte(respText)
	}

	needCert := parseBoolParam(getQueryParam(state.Params, "needcert", "needCert"))
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
	if dat := strings.TrimSpace(getQueryParam(state.Params, "dat", "data")); dat != "" {
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
	// Best-effort compatibility with camelCase variants used by some integrators.
	var compat batchRequestJSONCompat
	if err := json.Unmarshal(raw, &compat); err == nil {
		if !req.StopOnError {
			req.StopOnError = compat.StopOnError
		}
		if strings.TrimSpace(req.SubOp) == "" {
			req.SubOp = strings.TrimSpace(compat.SubOp)
		}
		if strings.TrimSpace(req.ExtraParams) == "" {
			req.ExtraParams = strings.TrimSpace(compat.ExtraParams)
		}
		if len(req.SingleSigns) == 0 && len(compat.SingleSigns) > 0 {
			req.SingleSigns = make([]batchSingleEntry, 0, len(compat.SingleSigns))
			for _, s := range compat.SingleSigns {
				req.SingleSigns = append(req.SingleSigns, batchSingleEntry{
					ID:          strings.TrimSpace(s.ID),
					SubOp:       strings.TrimSpace(s.SubOp),
					DataRef:     strings.TrimSpace(s.DataRef),
					Format:      strings.TrimSpace(s.Format),
					Algorithm:   strings.TrimSpace(s.Algorithm),
					ExtraParams: strings.TrimSpace(s.ExtraParams),
				})
			}
		}
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
		ExtraParams: strings.TrimSpace(xmlReq.ExtraParams),
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

func normalizeBatchSignID(id string) string {
	return strings.ToLower(strings.TrimSpace(id))
}

func buildBatchRemoteSignOptions(state *ProtocolState, req *batchRequest) (map[string]interface{}, map[string]map[string]interface{}) {
	global := buildProtocolSignOptions(state, "cades")
	if global == nil {
		global = map[string]interface{}{}
	}
	if req == nil {
		return global, nil
	}
	if strings.TrimSpace(req.ExtraParams) != "" {
		for k, v := range decodeBatchExtraParams(req.ExtraParams) {
			applyProtocolSignOption(global, k, v)
		}
	}
	perSign := make(map[string]map[string]interface{})
	for _, s := range req.SingleSigns {
		id := normalizeBatchSignID(s.ID)
		if id == "" || strings.TrimSpace(s.ExtraParams) == "" {
			continue
		}
		opts := map[string]interface{}{}
		for k, v := range decodeBatchExtraParams(s.ExtraParams) {
			applyProtocolSignOption(opts, k, v)
		}
		if len(opts) > 0 {
			perSign[id] = opts
		}
	}
	if len(perSign) == 0 {
		return global, nil
	}
	return global, perSign
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

func (s *WebSocketServer) executeRemoteTriphaseBatch(state *ProtocolState, rawBatch []byte, req *batchRequest, cert protocol.Certificate, isJSONBatch bool) (string, error) {
	preURL := strings.TrimSpace(getQueryParam(
		state.Params,
		"batchpresignerurl",
		"batchPreSignerUrl",
		"batchPreSignerURL",
	))
	postURL := strings.TrimSpace(getQueryParam(
		state.Params,
		"batchpostsignerurl",
		"batchPostSignerUrl",
		"batchPostSignerURL",
	))
	if preURL == "" || postURL == "" {
		return "", fmt.Errorf("SAF_03: Faltan URLs de prefirma/postfirma de lote")
	}

	type batchEncodingVariant struct {
		name string
		b64  string
	}
	type batchParamEncodingVariant struct {
		name   string
		encode func(string) string
	}
	batchVariants := []batchEncodingVariant{
		{name: "urlsafe", b64: base64.URLEncoding.EncodeToString(rawBatch)},
		{name: "std", b64: base64.StdEncoding.EncodeToString(rawBatch)},
	}
	paramEncodingVariants := []batchParamEncodingVariant{
		{name: "escape", encode: url.QueryEscape},
		{
			name: "escape_pct20",
			encode: func(v string) string {
				return strings.ReplaceAll(url.QueryEscape(v), "+", "%20")
			},
		},
		{name: "java_raw", encode: func(v string) string { return v }},
	}
	certVariants := buildBatchCertsParamVariants(cert)
	if len(certVariants) == 0 {
		certVariants = []string{buildBatchCertsParam(cert)}
	}
	if len(certVariants) == 0 {
		certVariants = []string{""}
	}
	batchParam := "xml"
	if isJSONBatch {
		batchParam = "json"
	}
	var (
		preRaw                   []byte
		preReq                   string
		preErr                   error
		selectedBatchVariantName = "urlsafe"
		selectedParamEncoding    = "escape"
		selectedCertParam        = certVariants[0]
		emptyPreRaw              []byte
		emptyPreReq              string
		emptyBatchVariantName    = "urlsafe"
		emptyParamEncodingName   = "escape"
		emptyCertParam           = certVariants[0]
	)
	preSuccess := false
	for _, batchVariant := range batchVariants {
		for _, certParam := range certVariants {
			for _, paramEncoding := range paramEncodingVariants {
				candidateReq := preURL + "?" + batchParam + "=" + paramEncoding.encode(batchVariant.b64) + "&certs=" + paramEncoding.encode(certParam)
				if isBatchCompatTraceEnabled() {
					log.Printf(
						"[Batch-TRACE] intento prefirma codif_batch=%s codif_params=%s certs=%s",
						batchVariant.name,
						paramEncoding.name,
						batchPayloadFingerprint(certParam),
					)
				}
				candidateRaw, candidateErr := batchHTTPPostWithRetry(candidateReq, "prefirma")
				if candidateErr != nil {
					preReq = candidateReq
					preErr = candidateErr
					var httpErr *batchHTTPError
					if errors.As(candidateErr, &httpErr) && httpErr != nil && shouldFallbackToFormBody(httpErr) {
						continue
					}
					return "", fmt.Errorf("%s", mapBatchRemoteHTTPError("prefirma", candidateReq, candidateErr))
				}
				if protoErr := detectBatchServiceProtocolError(candidateRaw, "prefirma"); protoErr != nil {
					return "", protoErr
				}
				if isJSONBatch {
					var probe batchPreResponse
					if err := json.Unmarshal(candidateRaw, &probe); err == nil && probe.TD == nil && len(probe.Results) == 0 {
						if len(emptyPreRaw) == 0 {
							emptyPreRaw = candidateRaw
							emptyPreReq = candidateReq
							emptyBatchVariantName = batchVariant.name
							emptyParamEncodingName = paramEncoding.name
							emptyCertParam = certParam
						}
						continue
					}
				}
				preReq = candidateReq
				preRaw = candidateRaw
				selectedBatchVariantName = batchVariant.name
				selectedParamEncoding = paramEncoding.name
				selectedCertParam = certParam
				preSuccess = true
				break
			}
			if preSuccess {
				break
			}
		}
		if preSuccess {
			break
		}
	}
	if !preSuccess {
		if len(emptyPreRaw) > 0 {
			preRaw = emptyPreRaw
			preReq = emptyPreReq
			selectedBatchVariantName = emptyBatchVariantName
			selectedParamEncoding = emptyParamEncodingName
			selectedCertParam = emptyCertParam
			preSuccess = true
		}
	}
	if !preSuccess {
		if preErr != nil {
			if mapped := mapBatchRemoteHTTPError("prefirma", preReq, preErr); !strings.Contains(mapped, "SAF_26: Error contactando servicio de prefirma de lote") || strings.TrimSpace(preReq) != "" {
				return "", fmt.Errorf("%s", mapped)
			}
			return "", fmt.Errorf("SAF_26: Error contactando servicio de prefirma de lote")
		}
		return "", fmt.Errorf("SAF_26: Error contactando servicio de prefirma de lote")
	}

	var tdSignedB64 string
	batchForPost := rawBatch
	remoteSignOptions, perSignRemoteOptions := buildBatchRemoteSignOptions(state, req)
	if isJSONBatch {
		var preResp batchPreResponse
		if err := json.Unmarshal(preRaw, &preResp); err != nil {
			return "", fmt.Errorf("SAF_27: Respuesta de prefirma de lote invalida")
		}
		normalizeBatchPreResponse(&preResp)
		emptyRetryDelays := []time.Duration{
			250 * time.Millisecond,
			500 * time.Millisecond,
			900 * time.Millisecond,
			1400 * time.Millisecond,
			2 * time.Second,
		}
		for emptyAttempt := 1; preResp.TD == nil && len(preResp.Results) == 0 && emptyAttempt <= len(emptyRetryDelays); emptyAttempt++ {
			log.Printf(
				"[Batch] prefirma vacia, sondeo %d/%d (espera=%s, codif=%s, params=%s): cuerpo=%q",
				emptyAttempt,
				len(emptyRetryDelays),
				emptyRetryDelays[emptyAttempt-1],
				selectedBatchVariantName,
				selectedParamEncoding,
				summarizeServerBody(string(preRaw)),
			)
			time.Sleep(emptyRetryDelays[emptyAttempt-1])
			preRawRetry, retryErr := batchHTTPPostWithRetry(preReq, "prefirma")
			if retryErr != nil {
				break
			}
			preRaw = preRawRetry
			var retryResp batchPreResponse
			if err := json.Unmarshal(preRawRetry, &retryResp); err != nil {
				break
			}
			normalizeBatchPreResponse(&retryResp)
			preResp = retryResp
		}
		if preResp.TD == nil || len(preResp.TD.SignInfo) == 0 {
			if preResp.TD != nil && len(preResp.TD.SignInfo) == 0 {
				log.Printf("[Batch] prefirma sin datos trifasicos: signinfo=0; results=%d cuerpo=%q", len(preResp.Results), summarizeServerBody(string(preRaw)))
			}
			out, mErr := json.Marshal(batchResponse{Signs: preResp.Results})
			if mErr != nil {
				return "", fmt.Errorf("SAF_12: Error preparando respuesta de lote")
			}
			// Si prefirma no devuelve firmas trifasicas no hay nada que postsignar.
			// Devolvemos el resultado de prefirma para evitar ERROR_POST espurio.
			if len(preResp.Results) == 0 {
				return "", fmt.Errorf("SAF_27: Prefirma de lote sin datos trifasicos ni resultados (%s)", summarizeServerBody(string(preRaw)))
			}
			return string(out), nil
		}

		tdSigned, err := signTriphaseData(preResp.TD, cert.ID, extractBatchAlgorithm(rawBatch), remoteSignOptions, perSignRemoteOptions)
		if err != nil {
			return "", fmt.Errorf("SAF_27: Error en firma trifasica de lote")
		}
		logBatchTriphaseIDSummary("prefirma_td", preResp.TD.SignInfo)
		logBatchTriphaseIDSummary("postfirma_td", tdSigned.SignInfo)
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
		tdSignedXML, err := signTriphaseDataXML(preRaw, cert.ID, extractBatchAlgorithmFromXML(rawBatch), remoteSignOptions, perSignRemoteOptions)
		if err != nil {
			return "", fmt.Errorf("SAF_27: Error en firma trifasica de lote")
		}
		tdSignedB64 = base64.URLEncoding.EncodeToString(tdSignedXML)
	}

	postBatchB64 := base64.URLEncoding.EncodeToString(batchForPost)
	if selectedBatchVariantName == "std" {
		postBatchB64 = base64.StdEncoding.EncodeToString(batchForPost)
	}
	selectedParamEncoder := url.QueryEscape
	if selectedParamEncoding == "escape_pct20" {
		selectedParamEncoder = func(v string) string {
			return strings.ReplaceAll(url.QueryEscape(v), "+", "%20")
		}
	} else if selectedParamEncoding == "java_raw" {
		selectedParamEncoder = func(v string) string { return v }
	}
	postReq := postURL + "?" + batchParam + "=" + selectedParamEncoder(postBatchB64) +
		"&certs=" + selectedParamEncoder(selectedCertParam) +
		"&tridata=" + selectedParamEncoder(tdSignedB64)
	if isJSONBatch {
		logBatchPostIDCheck(batchForPost, tdSignedB64)
	}
	postRaw, err := batchHTTPPostWithRetry(postReq, "postfirma")
	if err != nil {
		return "", fmt.Errorf("%s", mapBatchRemoteHTTPError("postfirma", postReq, err))
	}
	if protoErr := detectBatchServiceProtocolError(postRaw, "postfirma"); protoErr != nil {
		return "", protoErr
	}
	return string(postRaw), nil
}

func normalizeBatchPreResponse(preResp *batchPreResponse) {
	if preResp == nil || preResp.TD == nil {
		return
	}
	if len(preResp.TD.SignInfo) > 0 || len(preResp.TD.Signs) == 0 {
		return
	}
	flat := make([]triphaseSignInfoDTO, 0, 8)
	for _, block := range preResp.TD.Signs {
		if len(block.SignInfo) == 0 {
			continue
		}
		flat = append(flat, block.SignInfo...)
	}
	preResp.TD.SignInfo = flat
}

func buildBatchCertsParam(cert protocol.Certificate) string {
	derChain := collectBatchCertDERChain(cert)
	return encodeBatchCertChainURLSafe(derChain)
}

func buildBatchCertsParamVariants(cert protocol.Certificate) []string {
	derChain := collectBatchCertDERChain(cert)
	if len(derChain) == 0 {
		return nil
	}
	variants := make([]string, 0, 4)
	seen := make(map[string]struct{}, 4)
	addVariant := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		variants = append(variants, v)
	}
	addVariant(encodeBatchCertChainURLSafe(derChain))
	addVariant(encodeBatchCertChainStd(derChain))
	addVariant(encodeBatchCertChainURLSafe(derChain[:1]))
	addVariant(encodeBatchCertChainStd(derChain[:1]))
	return variants
}

func collectBatchCertDERChain(cert protocol.Certificate) [][]byte {
	added := make(map[[32]byte]struct{}, 4)
	derChain := make([][]byte, 0, 4)
	appendDER := func(der []byte) {
		if len(der) == 0 {
			return
		}
		sum := sha256.Sum256(der)
		if _, exists := added[sum]; exists {
			return
		}
		added[sum] = struct{}{}
		derChain = append(derChain, der)
	}

	// Java envía la cadena completa en orden hoja->emisores; usamos DER de Content y,
	// si PEM trae más bloques CERTIFICATE, los añadimos como posibles intermedios.
	appendDER(cert.Content)
	pemData := []byte(strings.TrimSpace(cert.PEM))
	for len(pemData) > 0 {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}
		if !strings.EqualFold(strings.TrimSpace(block.Type), "CERTIFICATE") || len(block.Bytes) == 0 {
			continue
		}
		if parsed, err := x509.ParseCertificate(block.Bytes); err == nil && parsed != nil {
			appendDER(parsed.Raw)
		} else {
			appendDER(block.Bytes)
		}
	}

	return derChain
}

func encodeBatchCertChainURLSafe(derChain [][]byte) string {
	if len(derChain) == 0 {
		return ""
	}
	parts := make([]string, 0, len(derChain))
	for _, der := range derChain {
		parts = append(parts, base64.URLEncoding.EncodeToString(der))
	}
	return strings.Join(parts, ";")
}

func encodeBatchCertChainStd(derChain [][]byte) string {
	if len(derChain) == 0 {
		return ""
	}
	parts := make([]string, 0, len(derChain))
	for _, der := range derChain {
		parts = append(parts, base64.StdEncoding.EncodeToString(der))
	}
	return strings.Join(parts, ";")
}

func batchHTTPPostWithRetry(rawURL string, phase string) ([]byte, error) {
	var lastErr error
	timeout := resolveBatchHTTPTimeout()
	maxAttempts := resolveBatchHTTPMaxAttempts()
	target := sanitizeBatchRemoteURL(rawURL)
	key := batchRemoteKey(rawURL)
	if until, blocked := batchRemoteIsOpen(key, time.Now()); blocked {
		return nil, &batchCircuitOpenError{Key: key, OpenUntil: until}
	}
	log.Printf("[Batch] solicitud remota destino=%s timeout=%s max_intentos=%d", target, timeout, maxAttempts)
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		body, err := batchHTTPPostFunc(rawURL)
		if err == nil {
			batchRemoteRecordSuccess(key)
			return body, nil
		}
		lastErr = err
		if !shouldRetryBatchHTTPError(err) || attempt == maxAttempts {
			break
		}
		log.Printf("[Batch] error remoto transitorio destino=%s intento=%d/%d err=%v", target, attempt, maxAttempts, err)
		backoff := time.Duration(math.Pow(2, float64(attempt-1))*150) * time.Millisecond
		time.Sleep(backoff)
	}
	batchRemoteRecordFailure(key, time.Now())
	logBatchRemoteFailureDiagnostics(rawURL, phase, lastErr)
	return nil, lastErr
}

func resolveBatchHTTPMaxAttempts() int {
	raw := strings.TrimSpace(os.Getenv("AUTOFIRMA_BATCH_HTTP_MAX_ATTEMPTS"))
	if raw == "" {
		return batchRemoteDefaultMaxAttempts
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return batchRemoteDefaultMaxAttempts
	}
	if n > batchRemoteMaxAttemptsCap {
		return batchRemoteMaxAttemptsCap
	}
	return n
}

func sanitizeBatchRemoteURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "<invalid-url>"
	}
	return strings.TrimSpace(u.Scheme + "://" + u.Host + u.Path)
}

func isBatchCompatTraceEnabled() bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("AUTOFIRMA_BATCH_COMPAT_TRACE")))
	return raw == "1" || raw == "true" || raw == "yes" || raw == "si"
}

func batchPayloadFingerprint(v string) string {
	s := strings.TrimSpace(v)
	if s == "" {
		return "len=0 sha12=e3b0c44298fc head=\"\" tail=\"\""
	}
	sum := sha256.Sum256([]byte(s))
	head := s
	if len(head) > 96 {
		head = head[:96]
	}
	tail := s
	if len(tail) > 64 {
		tail = tail[len(tail)-64:]
	}
	return fmt.Sprintf("len=%d sha12=%x head=%q tail=%q", len(s), sum[:6], head, tail)
}

func batchTransportModeLabel(sendQueryAsFormBody bool, formBody string) string {
	if sendQueryAsFormBody && strings.TrimSpace(formBody) != "" {
		return "post-form-urlencoded"
	}
	return "post-query"
}

func batchRemoteKey(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(u.Host))
}

func batchRemoteIsOpen(key string, now time.Time) (time.Time, bool) {
	if key == "" {
		return time.Time{}, false
	}
	batchRemoteBreakerMu.Lock()
	defer batchRemoteBreakerMu.Unlock()
	st, ok := batchRemoteBreaker[key]
	if !ok {
		return time.Time{}, false
	}
	if now.Before(st.openUntil) {
		return st.openUntil, true
	}
	return time.Time{}, false
}

func batchRemoteRecordSuccess(key string) {
	if key == "" {
		return
	}
	batchRemoteBreakerMu.Lock()
	delete(batchRemoteBreaker, key)
	batchRemoteBreakerMu.Unlock()
}

func batchRemoteRecordFailure(key string, now time.Time) {
	if key == "" {
		return
	}
	threshold := resolveBatchRemoteBreakerThreshold()
	cooldown := resolveBatchRemoteBreakerCooldown()
	batchRemoteBreakerMu.Lock()
	defer batchRemoteBreakerMu.Unlock()
	st := batchRemoteBreaker[key]
	st.failures++
	if st.failures >= threshold {
		st.openUntil = now.Add(cooldown)
		st.failures = 0
	}
	batchRemoteBreaker[key] = st
}

func resetBatchRemoteBreakerForTests() {
	batchRemoteBreakerMu.Lock()
	batchRemoteBreaker = map[string]batchRemoteBreakerState{}
	batchRemoteBreakerMu.Unlock()
}

func resolveBatchRemoteBreakerThreshold() int {
	raw := strings.TrimSpace(os.Getenv("AUTOFIRMA_BATCH_BREAKER_THRESHOLD"))
	if raw == "" {
		return batchRemoteBreakerThreshold
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return batchRemoteBreakerThreshold
	}
	if n > batchRemoteBreakerThresholdCap {
		return batchRemoteBreakerThresholdCap
	}
	return n
}

func resolveBatchRemoteBreakerCooldown() time.Duration {
	rawMS := strings.TrimSpace(os.Getenv("AUTOFIRMA_BATCH_BREAKER_COOLDOWN_MS"))
	if rawMS != "" {
		if n, err := strconv.Atoi(rawMS); err == nil && n > 0 {
			d := time.Duration(n) * time.Millisecond
			if d > batchRemoteBreakerCooldownCap {
				return batchRemoteBreakerCooldownCap
			}
			return d
		}
	}
	rawSec := strings.TrimSpace(os.Getenv("AUTOFIRMA_BATCH_BREAKER_COOLDOWN_SEC"))
	if rawSec != "" {
		if n, err := strconv.Atoi(rawSec); err == nil && n > 0 {
			d := time.Duration(n) * time.Second
			if d > batchRemoteBreakerCooldownCap {
				return batchRemoteBreakerCooldownCap
			}
			return d
		}
	}
	return batchRemoteBreakerCooldown
}

func shouldRetryBatchHTTPError(err error) bool {
	var httpErr *batchHTTPError
	if errors.As(err, &httpErr) && httpErr != nil {
		// Retry only transient HTTP conditions.
		switch {
		case httpErr.StatusCode == http.StatusRequestTimeout: // 408
			return true
		case httpErr.StatusCode == http.StatusTooManyRequests: // 429
			return true
		case httpErr.StatusCode >= 500:
			return true
		default:
			return false
		}
	}
	// Non-HTTP errors are typically transport/network errors.
	return true
}

func truncateBatchBodyForError(body []byte) string {
	s := strings.TrimSpace(string(body))
	if len(s) <= 180 {
		return s
	}
	return s[:180]
}

func mapBatchRemoteHTTPError(phase string, rawURL string, err error) string {
	var circuitErr *batchCircuitOpenError
	if errors.As(err, &circuitErr) && circuitErr != nil {
		return "SAF_26: Servicio de " + phase + " de lote temporalmente no disponible"
	}
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
	var transportErr *batchTransportError
	if errors.As(err, &transportErr) && transportErr != nil {
		msg := strings.ToLower(strings.TrimSpace(transportErr.Error()))
		switch {
		case strings.Contains(msg, "x509"), strings.Contains(msg, "tls"), strings.Contains(msg, "certificate"):
			extra := describeBatchRemoteTLSFailure(rawURL)
			base := "SAF_26: Error TLS verificando el certificado del servicio de " + phase + " de lote"
			if strings.TrimSpace(extra) != "" {
				return base + ". " + extra
			}
			return base
		case strings.Contains(msg, "no such host"), strings.Contains(msg, "lookup"):
			return "SAF_26: Error DNS resolviendo el servicio de " + phase + " de lote"
		}
	}
	return "SAF_26: Error contactando servicio de " + phase + " de lote"
}

func describeBatchRemoteTLSFailure(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u == nil || strings.TrimSpace(u.Hostname()) == "" {
		return ""
	}
	host := strings.TrimSpace(u.Hostname())
	port := strings.TrimSpace(u.Port())
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // Diagnóstico puntual para mostrar emisor/subject.
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return "Endpoint=" + host + " (" + summarizeServerBody(err.Error()) + ")"
	}
	defer conn.Close()

	st := conn.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return "Endpoint=" + host + " (sin certificado TLS remoto)"
	}
	leaf := st.PeerCertificates[0]
	subject := strings.TrimSpace(leaf.Subject.String())
	issuer := strings.TrimSpace(leaf.Issuer.String())
	if subject == "" {
		subject = "-"
	}
	if issuer == "" {
		issuer = "-"
	}

	roots, _ := x509.SystemCertPool()
	if roots == nil {
		roots = x509.NewCertPool()
	}
	inters := x509.NewCertPool()
	for i := 1; i < len(st.PeerCertificates); i++ {
		inters.AddCert(st.PeerCertificates[i])
	}
	if _, verifyErr := leaf.Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: inters,
		CurrentTime:   time.Now(),
	}); verifyErr != nil {
		if len(leaf.IssuingCertificateURL) > 0 {
			return fmt.Sprintf("Endpoint=%s; Certificado servidor=%s; Emisor=%s; URL cadena oficial=%s", host, subject, issuer, strings.Join(leaf.IssuingCertificateURL, ", "))
		}
		return fmt.Sprintf("Endpoint=%s; Certificado servidor=%s; Emisor=%s", host, subject, issuer)
	}
	return fmt.Sprintf("Endpoint=%s; Certificado servidor=%s; Emisor=%s", host, subject, issuer)
}

func logBatchRemoteFailureDiagnostics(rawURL string, phase string, err error) {
	target := sanitizeBatchRemoteURL(rawURL)
	log.Printf("[Batch] diagnóstico fallo remoto fase=%s destino=%s error=%v", phase, target, err)

	u, parseErr := url.Parse(rawURL)
	if parseErr != nil {
		log.Printf("[Batch] diagnóstico remoto: URL inválida (%v)", parseErr)
		return
	}
	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		log.Printf("[Batch] diagnóstico remoto: host vacío")
		return
	}
	port := strings.TrimSpace(u.Port())
	if port == "" {
		port = "443"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	ips, dnsErr := net.DefaultResolver.LookupHost(ctx, host)
	if dnsErr != nil {
		log.Printf("[Batch] diagnóstico remoto DNS host=%s error=%v", host, dnsErr)
	} else {
		log.Printf("[Batch] diagnóstico remoto DNS host=%s ips=%v", host, ips)
	}

	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, tlsErr := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // Solo diagnóstico de cadena recibida.
		MinVersion:         tls.VersionTLS12,
	})
	if tlsErr != nil {
		log.Printf("[Batch] diagnóstico remoto TLS host=%s handshake_error=%v", host, tlsErr)
		return
	}
	defer conn.Close()

	st := conn.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		log.Printf("[Batch] diagnóstico remoto TLS host=%s sin_certificados_peer", host)
		return
	}
	leaf := st.PeerCertificates[0]
	log.Printf(
		"[Batch] diagnóstico remoto TLS host=%s subject=%q issuer=%q not_before=%s not_after=%s",
		host,
		leaf.Subject.String(),
		leaf.Issuer.String(),
		leaf.NotBefore.Format(time.RFC3339),
		leaf.NotAfter.Format(time.RFC3339),
	)

	roots, _ := x509.SystemCertPool()
	if roots == nil {
		roots = x509.NewCertPool()
	}
	inters := x509.NewCertPool()
	for i := 1; i < len(st.PeerCertificates); i++ {
		inters.AddCert(st.PeerCertificates[i])
	}
	_, verifyErr := leaf.Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: inters,
		CurrentTime:   time.Now(),
	})
	if verifyErr != nil {
		log.Printf("[Batch] diagnóstico remoto TLS host=%s verify_error=%v", host, verifyErr)
	} else {
		log.Printf("[Batch] diagnóstico remoto TLS host=%s verify_ok", host)
	}
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
		return fmt.Errorf("SAF_27: Error en servicio de %s de lote (%s)", phase, summarizeServerBody(text))
	}
	if strings.Contains(up, "ERROR_POST") {
		return fmt.Errorf("SAF_27: Error en servicio de %s de lote (%s)", phase, summarizeServerBody(text))
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

func signTriphaseData(td *triphaseDataResponse, certID, algorithm string, signOptions map[string]interface{}, perSignOptions map[string]map[string]interface{}) (*triphaseDataRequest, error) {
	if td == nil {
		return nil, fmt.Errorf("nulo")
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
			return nil, fmt.Errorf("falta PRE")
		}
		preData, err := decodeAutoFirmaB64(strings.ReplaceAll(preB64, " ", "+"))
		if err != nil {
			return nil, err
		}
		opts := cloneSignOptions(signOptions)
		if len(perSignOptions) > 0 {
			signKey := normalizeBatchSignID(si.ID)
			if signKey == "" {
				signKey = normalizeBatchSignID(si.SignID)
			}
			if extra := perSignOptions[signKey]; len(extra) > 0 {
				for k, v := range extra {
					opts[k] = v
				}
			}
		}
		pk1B64, err := signPKCS1WithOptionsFunc(preData, certID, algorithm, opts)
		if err != nil {
			log.Printf("[Batch] fallo firmando PKCS1 id=%s err=%v", si.ID, err)
			return nil, err
		}
		params["PK1"] = pk1B64
		postID := strings.TrimSpace(si.ID)
		postSignID := strings.TrimSpace(si.SignID)
		if postID == "" {
			postID = postSignID
		}
		if postID == "" {
			postID = strings.TrimSpace(params["ID"])
		}
		out.SignInfo = append(out.SignInfo, triphaseSignInfoDTO{
			ID:     postID,
			SignID: postSignID,
			Params: params,
		})
	}
	return out, nil
}

func signTriphaseDataXML(rawTD []byte, certID, algorithm string, signOptions map[string]interface{}, perSignOptions map[string]map[string]interface{}) ([]byte, error) {
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
			return nil, fmt.Errorf("falta PRE")
		}
		preData, err := decodeAutoFirmaB64(strings.ReplaceAll(preB64, " ", "+"))
		if err != nil {
			return nil, err
		}
		opts := cloneSignOptions(signOptions)
		if len(perSignOptions) > 0 {
			signKey := normalizeBatchSignID(td.Firmas.Firmas[i].ID)
			if signKey == "" {
				signKey = normalizeBatchSignID(td.Firmas.Firmas[i].SignID)
			}
			if extra := perSignOptions[signKey]; len(extra) > 0 {
				for k, v := range extra {
					opts[k] = v
				}
			}
		}
		pk1B64, err := signPKCS1WithOptionsFunc(preData, certID, algorithm, opts)
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

func cloneSignOptions(src map[string]interface{}) map[string]interface{} {
	if len(src) == 0 {
		return map[string]interface{}{}
	}
	out := make(map[string]interface{}, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
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

func logBatchTriphaseIDSummary(stage string, items []triphaseSignInfoDTO) {
	if len(items) == 0 {
		log.Printf("[Batch] %s: sin firmas en tri-fase", stage)
		return
	}
	parts := make([]string, 0, len(items))
	for _, it := range items {
		id := strings.TrimSpace(it.ID)
		signID := strings.TrimSpace(it.SignID)
		if id == "" {
			id = "-"
		}
		if signID == "" {
			signID = "-"
		}
		parts = append(parts, "id="+id+"/signid="+signID)
	}
	log.Printf("[Batch] %s: firmas=%d [%s]", stage, len(items), strings.Join(parts, ", "))
}

func logBatchPostIDCheck(rawBatch []byte, tdSignedB64 string) {
	var root map[string]interface{}
	if err := json.Unmarshal(rawBatch, &root); err != nil {
		log.Printf("[Batch] post-id-check: lote JSON no parseable (%v)", err)
		return
	}
	ss, ok := root["singlesigns"].([]interface{})
	if !ok {
		log.Printf("[Batch] post-id-check: sin singlesigns")
		return
	}
	want := make([]string, 0, len(ss))
	for _, it := range ss {
		m, ok := it.(map[string]interface{})
		if !ok {
			continue
		}
		id, _ := m["id"].(string)
		id = strings.TrimSpace(id)
		if id != "" {
			want = append(want, id)
		}
	}

	tdRaw, err := base64.URLEncoding.DecodeString(strings.TrimSpace(tdSignedB64))
	if err != nil {
		log.Printf("[Batch] post-id-check: tridata no decodificable (%v)", err)
		return
	}
	var td triphaseDataRequest
	if err := json.Unmarshal(tdRaw, &td); err != nil {
		log.Printf("[Batch] post-id-check: tridata JSON no parseable (%v)", err)
		return
	}
	gotMap := make(map[string]struct{}, len(td.SignInfo))
	for _, si := range td.SignInfo {
		id := strings.TrimSpace(si.ID)
		if id == "" {
			id = strings.TrimSpace(si.SignID)
		}
		if id != "" {
			gotMap[id] = struct{}{}
		}
	}
	missing := make([]string, 0)
	for _, id := range want {
		if _, ok := gotMap[id]; !ok {
			missing = append(missing, id)
		}
	}
	if len(missing) == 0 {
		log.Printf("[Batch] post-id-check: OK ids_lote=%d ids_trifase=%d", len(want), len(gotMap))
		return
	}
	log.Printf("[Batch] post-id-check: faltan_ids_en_trifase=%v ids_lote=%d ids_trifase=%d", missing, len(want), len(gotMap))
}

func (s *WebSocketServer) selectBatchSigningCertificate(state *ProtocolState) (protocol.Certificate, string) {
	certs, err := loadCertificatesForState(state)
	if err != nil {
		return protocol.Certificate{}, "SAF_08: Error accediendo al almacen de certificados"
	}
	certs, storeFilter := filterSelectCertByDefaultStore(certs, state)
	if len(certs) == 0 {
		return protocol.Certificate{}, "SAF_19: No hay certificados disponibles"
	}

	resetSticky := parseBoolParam(getQueryParam(state.Params, "resetsticky", "resetSticky"))
	sticky := parseBoolParam(getQueryParam(state.Params, "sticky"))
	if resetSticky {
		s.stickyID = ""
	}
	if sticky && s.stickyID != "" {
		if idx := findCertificateIndexByID(certs, s.stickyID); idx >= 0 {
			return certs[idx], ""
		}
	}

	filtered, filterOpts := applySelectCertFilters(certs, state)
	if len(filtered) == 0 {
		filtered = certs
	}
	log.Printf("[Batch] cert candidates total=%d filtered=%d store_filter=%s", len(certs), len(filtered), storeFilter)
	idx := findPreferredCertificateIndex(filtered)
	if idx < 0 {
		return protocol.Certificate{}, "SAF_19: No hay certificados disponibles"
	}

	autoWithoutDialog := filterOpts.forceAutoSelection || (filterOpts.autoSelectWhenSingle && len(filtered) == 1)
	if normalizeProtocolAction(state.Action) == "batch" && s.ui != nil {
		// En flujo batch lanzado por protocolo web, la selección debe hacerse en la
		// ventana principal (lista de certificados) para evitar diálogos duplicados.
		autoWithoutDialog = true
		if s.ui.SelectedCert >= 0 && s.ui.SelectedCert < len(s.ui.Certs) {
			selectedID := strings.TrimSpace(s.ui.Certs[s.ui.SelectedCert].ID)
			if selectedID != "" {
				if uiIdx := findCertificateIndexByID(filtered, selectedID); uiIdx >= 0 {
					idx = uiIdx
				} else {
					return protocol.Certificate{}, "SAF_08: El certificado seleccionado no está disponible para este lote"
				}
			}
		}
	}
	if !autoWithoutDialog {
		if s.ui == nil {
			return protocol.Certificate{}, "SAF_09: Interfaz de firma no disponible"
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
	}

	if sticky {
		s.stickyID = filtered[idx].ID
	}
	chosen := filtered[idx]
	log.Printf(
		"[Batch] certificado seleccionado nombre=%q origen=%s apto=%t serie=%s id=%s",
		certificateBestDisplayName(chosen),
		strings.TrimSpace(chosen.Source),
		chosen.CanSign,
		strings.TrimSpace(chosen.SerialNumber),
		chosen.ID,
	)
	return chosen, ""
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

func (s *WebSocketServer) executeBatchSingle(state *ProtocolState, item batchSingleEntry, req *batchRequest, certID string, globalExtra map[string]string) batchSingleResult {
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
	operation, counterTargetHint, opErr := resolveBatchOperation(item.SubOp, req.SubOp)
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
	if operation == batchOperationCounterSign && strings.TrimSpace(counterTargetHint) != "" {
		if _, hasTarget := opts["target"]; !hasTarget {
			opts["target"] = counterTargetHint
		}
	}
	expandProtocolPolicyOptions(opts, format)
	applyProtocolStoreHints(opts, state)

	dataB64 := base64.StdEncoding.EncodeToString(dataBytes)
	signFunc := signDataFunc
	switch operation {
	case batchOperationCoSign:
		signFunc = coSignDataFunc
	case batchOperationCounterSign:
		signFunc = counterSignDataFunc
	}
	pin := signOptionString(opts, "_pin", "pin")
	sigB64, signErr := signFunc(dataB64, certID, pin, format, opts)
	if signErr != nil {
		result.Result = batchResultError
		result.Description = signErr.Error()
		return result
	}
	result.Signature = sigB64
	return result
}

func resolveBatchOperation(singleOp, globalOp string) (string, string, error) {
	op := strings.TrimSpace(singleOp)
	if op == "" {
		op = strings.TrimSpace(globalOp)
	}
	if op == "" {
		return batchOperationSign, "", nil
	}
	switch strings.ToLower(op) {
	case "sign", "firmar":
		return batchOperationSign, "", nil
	case "cosign", "cofirmar":
		return batchOperationCoSign, "", nil
	case "countersign", "contrafirmar":
		return batchOperationCounterSign, "", nil
	case "contrafirmar_arbol":
		return batchOperationCounterSign, "tree", nil
	case "contrafirmar_hojas":
		return batchOperationCounterSign, "leafs", nil
	default:
		return "", "", fmt.Errorf("Operacion de lote no soportada")
	}
}

func resolveBatchDataReference(ref string) ([]byte, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, fmt.Errorf("vacío")
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
