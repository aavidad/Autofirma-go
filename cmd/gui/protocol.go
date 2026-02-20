// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"autofirma-host/pkg/version"
	// Necesario para padding
	"crypto/des"
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
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultAllowedSigningDomains = "*.gob.es,*.dipgra.es,*.guadaltel.es,localhost,127.0.0.1,::1"

var confirmFirstDomainUseFunc = protocolConfirmFirstDomainUseDialog

var trustedSigningDomainsState = struct {
	mu     sync.Mutex
	loaded bool
	items  map[string]bool
}{}

type trustedSigningDomainsFile struct {
	Domains []string `json:"domains"`
}

// Estructuras XML para análisis de manifiesto.
type xmlEntry struct {
	Key   string `xml:"k,attr"`
	Value string `xml:"v,attr"`
}
type xmlRoot struct {
	XMLName xml.Name
	Entries []xmlEntry `xml:"e"`
}

type ProtocolState struct {
	IsActive             bool
	RTServlet            string
	STServlet            string // URL dedicada de almacenamiento
	FileID               string
	RequestID            string // fileid original de la URI (usado en el bucle WAIT)
	Key                  string
	Action               string // "sign"
	SourceURL            string
	Params               url.Values // Conserva todos los parámetros
	SignFormat           string     // Formato del XML: "CAdES", "PAdES", "XAdES"
	MinimumClientVersion string
	JavaScriptVersion    int
	ActiveWaiting        bool
	ProtocolVersion      int
}

var errMinimumClientVersionNotSatisfied = errors.New("versión mínima de cliente no satisfecha")
var errUnsupportedProcedureVersion = errors.New("versión de procedimiento no soportada")

// ParseProtocolURI analiza una URI "afirma://...".
func ParseProtocolURI(uriString string) (*ProtocolState, error) {
	// Elimina "afirma://" para parsear como URL si aplica.
	u, err := url.Parse(uriString)
	if err != nil {
		return nil, err
	}

	q := u.Query()

	state := &ProtocolState{
		IsActive:          true,
		SourceURL:         uriString,
		Action:            normalizeProtocolAction(extractProtocolAction(u)),
		Params:            q, // Conserva todos los parámetros
		JavaScriptVersion: 1,
		ProtocolVersion:   1,
	}
	queryAction := normalizeProtocolAction(getQueryParam(q, "op", "operation", "action"))
	if queryAction != "" {
		if state.Action != "" && state.Action != queryAction {
			log.Printf("[Protocol] Acción en host/path (%s) distinta de query-op (%s), se prioriza query-op", state.Action, queryAction)
		}
		state.Action = queryAction
	} else if state.Action == "" {
		state.Action = queryAction
	}
	state.MinimumClientVersion = getQueryParam(q, "mcv")
	jvc := strings.TrimSpace(getQueryParam(q, "jvc"))
	if jvc != "" {
		if parsed, convErr := strconv.Atoi(jvc); convErr == nil {
			state.JavaScriptVersion = parsed
		}
	}
	if state.JavaScriptVersion < 1 {
		log.Printf("[Protocol] Código de versión JavaScript por debajo del mínimo seguro (jvc=%d requerido>=1)", state.JavaScriptVersion)
	}
	if state.MinimumClientVersion != "" {
		requestedIsGreater, cmpErr := isRequestedVersionGreater(state.MinimumClientVersion, version.CurrentVersion)
		if cmpErr != nil {
			return nil, fmt.Errorf("valor de mcv invalido: %w", cmpErr)
		}
		if requestedIsGreater {
			return nil, fmt.Errorf("%w: mcv=%s current=%s", errMinimumClientVersionNotSatisfied, state.MinimumClientVersion, version.CurrentVersion)
		}
	}
	if vRaw := strings.TrimSpace(getQueryParam(q, "v", "ver")); vRaw != "" {
		if parsed, convErr := strconv.Atoi(vRaw); convErr == nil {
			state.ProtocolVersion = parsed
		}
	}
	if state.ProtocolVersion < 0 || state.ProtocolVersion > 4 {
		return nil, fmt.Errorf("%w: v=%d", errUnsupportedProcedureVersion, state.ProtocolVersion)
	}

	state.FileID = getQueryParam(q, "fileid", "id", "fileId", "requestId")
	state.RequestID = state.FileID

	state.Key = getQueryParam(q, "key", "cipherKey")

	state.RTServlet = getQueryParam(q, "rtservlet", "retrieveservlet", "rtServlet", "retrieveServlet")

	state.STServlet = getQueryParam(q, "stservlet", "storageservlet", "stServlet", "storageServlet")

	state.SignFormat = getQueryParam(q, "format", "signFormat")
	state.ActiveWaiting = parseBoolParam(getQueryParam(q, "aw"))

	// En modo WebSocket, el protocolo Java permite sign/cosign/countersign sin
	// servlet/id (servicesRequired=false) y resuelve datos por otros caminos.
	// También permite operaciones locales interactivas (save/load/selectcert/signandsave/batch).
	// Se mantiene validación estricta cuando no existe ningún parámetro útil de sesión/ruta.
	if state.RTServlet == "" && state.STServlet == "" && state.FileID == "" {
		switch normalizeProtocolAction(state.Action) {
		case "sign", "cosign", "countersign":
			if getQueryParam(q, "idsession", "idSession", "dat", "data", "ksb64", "properties") == "" {
				return nil, fmt.Errorf("parámetros insuficientes en la solicitud (falta id, rtservlet o stservlet)")
			}
		case "save", "load", "selectcert", "signandsave", "batch":
			// Permitido en modo WebSocket/local.
		default:
			return nil, fmt.Errorf("parámetros insuficientes en la solicitud (falta id, rtservlet o stservlet)")
		}
	}

	if state.RTServlet == "" {
		log.Printf("[Protocol] No se proporcionó 'rtservlet'. Puede ser una firma de archivo local o un flujo basado en sesión.")
	}

	return state, nil
}

type parsedClientVersion struct {
	parts  []int
	suffix string
}

func isRequestedVersionGreater(requested string, current string) (bool, error) {
	reqV, err := parseClientVersion(requested)
	if err != nil {
		return false, err
	}
	curV, err := parseClientVersion(current)
	if err != nil {
		return false, err
	}
	return compareParsedClientVersion(reqV, curV) > 0, nil
}

func parseClientVersion(v string) (*parsedClientVersion, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, fmt.Errorf("version vacia")
	}
	rawParts := strings.Split(v, ".")
	if len(rawParts) == 0 {
		return nil, fmt.Errorf("version vacia")
	}
	out := &parsedClientVersion{
		parts: make([]int, 0, len(rawParts)),
	}
	for i := 0; i < len(rawParts)-1; i++ {
		part := strings.TrimSpace(rawParts[i])
		if part == "" {
			return nil, fmt.Errorf("parte vacia en version")
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("parte no numerica en version")
		}
		out.parts = append(out.parts, n)
	}
	last := strings.TrimSpace(rawParts[len(rawParts)-1])
	if last == "" {
		return nil, fmt.Errorf("parte final vacia en version")
	}
	limit := len(last)
	for i := 0; i < len(last); i++ {
		if last[i] < '0' || last[i] > '9' {
			limit = i
			break
		}
	}
	if limit == 0 {
		return nil, fmt.Errorf("parte final no numerica en version")
	}
	lastNum, err := strconv.Atoi(last[:limit])
	if err != nil {
		return nil, fmt.Errorf("parte final no numerica en version")
	}
	out.parts = append(out.parts, lastNum)
	if limit < len(last) {
		out.suffix = last[limit:]
	}
	return out, nil
}

func compareParsedClientVersion(a *parsedClientVersion, b *parsedClientVersion) int {
	min := len(a.parts)
	if len(b.parts) < min {
		min = len(b.parts)
	}
	for i := 0; i < min; i++ {
		if a.parts[i] > b.parts[i] {
			return 1
		}
		if a.parts[i] < b.parts[i] {
			return -1
		}
	}
	if len(a.parts) > len(b.parts) {
		return 1
	}
	if len(a.parts) < len(b.parts) {
		return -1
	}

	as := a.suffix
	bs := b.suffix
	if strings.EqualFold(as, bs) {
		return 0
	}
	if (as == "" || as[0] != ' ') && len(bs) > 0 && bs[0] == ' ' {
		return 1
	}
	if (bs == "" || bs[0] != ' ') && len(as) > 0 && as[0] == ' ' {
		return -1
	}
	if as == "" && len(bs) > 0 && bs[0] != ' ' {
		return -1
	}
	if bs == "" && len(as) > 0 && as[0] != ' ' {
		return 1
	}
	las := strings.ToLower(as)
	lbs := strings.ToLower(bs)
	if las > lbs {
		return 1
	}
	if las < lbs {
		return -1
	}
	return 0
}

func extractProtocolAction(u *url.URL) string {
	if u == nil {
		return ""
	}
	action := strings.TrimSpace(u.Host)
	if action != "" {
		return action
	}
	path := strings.TrimSpace(u.Path)
	path = strings.Trim(path, "/")
	if path == "" {
		return ""
	}
	if i := strings.Index(path, "/"); i >= 0 {
		path = path[:i]
	}
	return strings.TrimSpace(path)
}

func getQueryParam(q url.Values, keys ...string) string {
	if q == nil || len(keys) == 0 {
		return ""
	}
	for _, k := range keys {
		if v := strings.TrimSpace(q.Get(k)); v != "" {
			return v
		}
	}
	for rawKey, vals := range q {
		if len(vals) == 0 {
			continue
		}
		for _, k := range keys {
			if strings.EqualFold(strings.TrimSpace(rawKey), strings.TrimSpace(k)) {
				v := strings.TrimSpace(vals[len(vals)-1])
				if v != "" {
					return v
				}
			}
		}
	}
	return ""
}

func normalizeProtocolAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "firmar":
		return "sign"
	case "cofirmar":
		return "cosign"
	case "contrafirmar", "contrafirmar_arbol", "contrafirmar_hojas":
		return "countersign"
	default:
		return strings.ToLower(strings.TrimSpace(action))
	}
}

func protocolActionLabelES(action string) string {
	switch normalizeProtocolAction(action) {
	case "sign":
		return "firma"
	case "cosign":
		return "cofirma"
	case "countersign":
		return "contrafirma"
	case "selectcert":
		return "identificación (selección de certificado)"
	case "load":
		return "carga de fichero"
	case "save":
		return "guardado de fichero"
	case "signandsave":
		return "firma y guardado"
	case "batch":
		return "firma por lotes"
	case "service":
		return "servicio fragmentado"
	case "websocket":
		return "arranque websocket"
	default:
		return "operación desconocida"
	}
}

func protocolRequestSummaryES(state *ProtocolState) string {
	if state == nil {
		return "solicitud inválida (estado vacío)"
	}
	format := normalizeProtocolFormat(state.SignFormat)
	if format == "" {
		format = "-"
	}
	rt := "no"
	if strings.TrimSpace(state.RTServlet) != "" {
		rt = "sí"
	}
	st := "no"
	if strings.TrimSpace(state.STServlet) != "" {
		st = "sí"
	}
	fileID := strings.TrimSpace(state.FileID)
	if fileID == "" {
		fileID = "-"
	}
	return fmt.Sprintf(
		"tipo=%s accion=%s formato=%s id=%s rtservlet=%s stservlet=%s",
		protocolActionLabelES(state.Action),
		normalizeProtocolAction(state.Action),
		format,
		fileID,
		rt,
		st,
	)
}

func allowedSigningDomainPatterns() []string {
	raw := strings.TrimSpace(os.Getenv("AUTOFIRMA_ALLOWED_SIGN_DOMAINS"))
	if raw == "" {
		raw = defaultAllowedSigningDomains
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.ToLower(strings.TrimSpace(p))
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}

func isHostAllowedByPattern(host string, pattern string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if host == "" || pattern == "" {
		return false
	}
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*.")
		if suffix == "" {
			return false
		}
		return strings.HasSuffix(host, "."+suffix)
	}
	return false
}

func validateSigningServerURL(rawURL string, fieldName string) error {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%s inválido: %w", fieldName, err)
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "" {
		return fmt.Errorf("%s inválido: host vacío", fieldName)
	}
	allowed := allowedSigningDomainPatterns()
	ok := false
	for _, pattern := range allowed {
		if isHostAllowedByPattern(host, pattern) {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("%s fuera de lista blanca: %s (permitidos: %s)", fieldName, host, strings.Join(allowed, ","))
	}
	if !strings.EqualFold(u.Scheme, "https") && host != "localhost" && host != "127.0.0.1" && host != "::1" {
		return fmt.Errorf("%s debe usar HTTPS para host remoto: %s", fieldName, host)
	}
	if err := ensureTrustedSigningDomain(host); err != nil {
		return fmt.Errorf("%s bloqueado por política de confianza: %w", fieldName, err)
	}
	return nil
}

func trustedSigningDomainsPath() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return ""
	}
	return filepath.Join(home, ".config", "AutofirmaDipgra", "trusted_sign_domains.json")
}

func loadTrustedSigningDomainsLocked() {
	trustedSigningDomainsState.items = make(map[string]bool)
	path := trustedSigningDomainsPath()
	if strings.TrimSpace(path) == "" {
		trustedSigningDomainsState.loaded = true
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		trustedSigningDomainsState.loaded = true
		return
	}
	var payload trustedSigningDomainsFile
	if err := json.Unmarshal(data, &payload); err != nil {
		trustedSigningDomainsState.loaded = true
		return
	}
	for _, host := range payload.Domains {
		h := strings.ToLower(strings.TrimSpace(host))
		if h == "" {
			continue
		}
		trustedSigningDomainsState.items[h] = true
	}
	trustedSigningDomainsState.loaded = true
}

func saveTrustedSigningDomainsLocked() {
	path := trustedSigningDomainsPath()
	if strings.TrimSpace(path) == "" {
		return
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return
	}
	domains := make([]string, 0, len(trustedSigningDomainsState.items))
	for host := range trustedSigningDomainsState.items {
		domains = append(domains, host)
	}
	payload := trustedSigningDomainsFile{Domains: domains}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0600)
}

func isImplicitlyTrustedDomain(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func ensureTrustedSigningDomain(host string) error {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || isImplicitlyTrustedDomain(host) {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("AUTOFIRMA_DOMAIN_TRUST_AUTO_ALLOW")), "1") {
		return nil
	}

	trustedSigningDomainsState.mu.Lock()
	if !trustedSigningDomainsState.loaded {
		loadTrustedSigningDomainsLocked()
	}
	if trustedSigningDomainsState.items[host] {
		trustedSigningDomainsState.mu.Unlock()
		return nil
	}
	trustedSigningDomainsState.mu.Unlock()

	accepted, err := confirmFirstDomainUseFunc(host)
	if err != nil {
		return err
	}
	if !accepted {
		return fmt.Errorf("el usuario no confió en el dominio %s", host)
	}

	trustedSigningDomainsState.mu.Lock()
	if !trustedSigningDomainsState.loaded {
		loadTrustedSigningDomainsLocked()
	}
	trustedSigningDomainsState.items[host] = true
	saveTrustedSigningDomainsLocked()
	trustedSigningDomainsState.mu.Unlock()
	return nil
}

func normalizeSigningDomainInput(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return ""
	}
	if strings.Contains(v, "://") {
		if u, err := url.Parse(v); err == nil {
			v = strings.ToLower(strings.TrimSpace(u.Hostname()))
		}
	}
	if i := strings.Index(v, "/"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	if i := strings.Index(v, ":"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	return v
}

func trustedSigningDomainsSnapshot() []string {
	trustedSigningDomainsState.mu.Lock()
	defer trustedSigningDomainsState.mu.Unlock()
	if !trustedSigningDomainsState.loaded {
		loadTrustedSigningDomainsLocked()
	}
	out := make([]string, 0, len(trustedSigningDomainsState.items))
	for host := range trustedSigningDomainsState.items {
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

func addTrustedSigningDomain(domain string) error {
	host := normalizeSigningDomainInput(domain)
	if host == "" {
		return fmt.Errorf("dominio vacío")
	}
	trustedSigningDomainsState.mu.Lock()
	defer trustedSigningDomainsState.mu.Unlock()
	if !trustedSigningDomainsState.loaded {
		loadTrustedSigningDomainsLocked()
	}
	trustedSigningDomainsState.items[host] = true
	saveTrustedSigningDomainsLocked()
	return nil
}

func removeTrustedSigningDomain(domain string) error {
	host := normalizeSigningDomainInput(domain)
	if host == "" {
		return fmt.Errorf("dominio vacío")
	}
	trustedSigningDomainsState.mu.Lock()
	defer trustedSigningDomainsState.mu.Unlock()
	if !trustedSigningDomainsState.loaded {
		loadTrustedSigningDomainsLocked()
	}
	delete(trustedSigningDomainsState.items, host)
	saveTrustedSigningDomainsLocked()
	return nil
}

func (p *ProtocolState) DownloadFile() (string, error) {
	if p.RTServlet == "" {
		log.Println("[Protocol] RTServlet vacío, se omite la descarga.")
		return "", nil // Sin error, simplemente no hay nada que descargar.
	}
	if err := validateSigningServerURL(p.RTServlet, "rtservlet"); err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 30 * time.Second}

	// Función auxiliar para intentar descarga.
	attempt := func(method string) (string, []byte, error) {
		reqURL, err := url.Parse(p.RTServlet)
		if err != nil {
			return "", nil, err
		}

		// Preparar parámetros estrictamente estándar (como cliente Java).
		data := url.Values{}

		// Forzar/sobrescribir operaciones críticas.
		data.Set("op", "get")
		data.Set("v", "1_0")
		data.Set("id", p.FileID)

		// NOTA: el cliente Java (IntermediateServerUtil) NO envía 'key' ni extras
		// en retrieveData. Solo envía op, v e id.
		// La clave se usa solo localmente para descifrar.

		var req *http.Request
		if method == "GET" {
			reqURL.RawQuery = data.Encode() // Reemplaza cualquier query existente
			req, err = http.NewRequest("GET", reqURL.String(), nil)
			log.Printf("[Protocol] URL GET: %s", reqURL.String()) // Registrar URL completa
		} else {
			// POST (respaldo si GET falla/no está permitido)
			// En POST, el cliente Java quita query de la URL y la pone en el body.
			reqURL.RawQuery = ""
			encodedData := data.Encode()
			req, err = http.NewRequest("POST", reqURL.String(), strings.NewReader(encodedData))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			log.Printf("[Protocol] Datos POST: %s", encodedData) // Registrar body
		}

		if err != nil {
			return "", nil, err
		}

		// Cabeceras similares a AutoFirma
		req.Header.Set("User-Agent", "AutoFirma/1.6.5") // Usar versión estándar
		req.Header.Set("Accept", "*/*")

		log.Printf("[Protocol] Intentando %s %s", method, p.RTServlet)

		resp, err := client.Do(req)
		if err != nil {
			return "", nil, err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", nil, err
		}

		log.Printf("[Protocol] Estado: %d, LongitudContenido: %d", resp.StatusCode, len(body))

		if resp.StatusCode != 200 {
			return "", body, fmt.Errorf("error del servidor %d", resp.StatusCode)
		}

		return "", body, nil
	}

	// Intentar GET
	_, body, err := attempt("GET")

	// Comprobar si es válido (tamaño > 100, etc., o que no empiece por ERR-)
	if err == nil && len(body) > 100 { // Reduced threshold slightly
		if strings.HasPrefix(strings.ToLower(string(body)), "err-") {
			log.Printf("[Protocol] El servidor devolvió contenido de error: %s", string(body))
		} else {
			// Éxito con GET
			return saveTemp(body, p.FileID, p.Key)
		}
	}

	if len(body) < 500 {
		log.Printf("[Protocol] Respuesta GET demasiado pequeña: %s", string(body))
	}

	// Intentar POST como respaldo
	log.Println("[Protocol] GET falló o devolvió contenido pequeño. Probando POST...")
	_, bodyPost, errPost := attempt("POST")
	if errPost == nil && len(bodyPost) > 200 {
		return saveTemp(bodyPost, p.FileID, p.Key)
	}

	// Fallo final
	if len(bodyPost) < 500 {
		log.Printf("[Protocol] Respuesta POST: %s", string(bodyPost))
		return "", fmt.Errorf("descarga fallida. El servidor devolvió: %s", string(bodyPost))
	}

	return "", fmt.Errorf("no se pudo descargar el documento (GET y POST fallaron)")
}

func saveTemp(data []byte, fileID string, key string) (string, error) {
	// Usar fileID saneado para el nombre
	safeID := filepath.Base(fileID)
	if safeID == "" || safeID == "." {
		safeID = "autofirma_doc"
	}

	// AutoFirma cifra datos con formato: PADDING.ENCRYPTED_BASE64
	// Primero, intentar descifrar si hay clave
	if key != "" {
		dataStr := string(data)

		// Comprobar si tiene formato PADDING.DATA
		if strings.Contains(dataStr, ".") {
			parts := strings.SplitN(dataStr, ".", 2)
			if len(parts) == 2 {
				padding, err := strconv.Atoi(parts[0])
				if err == nil {
					// Convertir URL-safe Base64 a estándar
					b64Data := strings.ReplaceAll(parts[1], "-", "+")
					b64Data = strings.ReplaceAll(b64Data, "_", "/")

					// Decodificar Base64
					encrypted, err := base64.StdEncoding.DecodeString(b64Data)
					if err == nil {
						// Descifrar con DES
						decrypted, err := decryptDES(encrypted, []byte(key))
						if err == nil {
							// Quitar padding
							if padding > 0 && padding < len(decrypted) {
								decrypted = decrypted[:len(decrypted)-padding]
							}
							log.Printf("[Protocol] Datos descifrados correctamente (relleno=%d, tamaño=%d)", padding, len(decrypted))
							data = decrypted
						} else {
							log.Printf("[Protocol] Falló el descifrado DES: %v", err)
						}
					}
				}
			}
		}
	}

	// Intentar decodificación Base64 (robusta)
	decoded := false
	inputs := []string{string(data)}

	// Si contiene un punto, puede ser [VERSION].[DATA]
	if strings.Contains(string(data), ".") {
		parts := strings.SplitN(string(data), ".", 2)
		if len(parts) == 2 {
			inputs = append(inputs, parts[1])
		}
	}

	for _, input := range inputs {
		if decoded {
			break
		}
		// Limpiar espacios
		input = strings.TrimSpace(input)

		// Probar varios decodificadores
		decoders := []*base64.Encoding{
			base64.StdEncoding,
			base64.URLEncoding,
			base64.RawURLEncoding,
			base64.RawStdEncoding,
		}

		for _, enc := range decoders {
			decodedBytes, err := enc.DecodeString(input)
			if err == nil && len(decodedBytes) > 0 {
				// Comprobar cabecera
				strDecoded := string(decodedBytes)
				isPDF := len(decodedBytes) > 4 && string(decodedBytes[:4]) == "%PDF"
				isXML := strings.Contains(strDecoded, "<?xml") || strings.Contains(strDecoded, "<afirma") || strings.Contains(strDecoded, "<request")

				if isPDF || isXML {
					debugLen := 10
					if len(decodedBytes) < 10 {
						debugLen = len(decodedBytes)
					}
					log.Printf("[Protocol] Base64 decodificado correctamente. Cabecera: %x", decodedBytes[:debugLen])
					data = decodedBytes
					decoded = true
					break
				}
			}
		}
	}

	// Detectar extensión
	ext := ".pdf" // Por defecto
	strData := string(data)

	// Depuración: registrar primeros 50 bytes para verificar contenido
	debugLen := 50
	if len(data) < 50 {
		debugLen = len(data)
	}
	log.Printf("[Protocol] Cabecera de fichero detectada: %x (texto: %q)", data[:debugLen], string(data[:debugLen]))

	if len(data) > 4 && string(data[:4]) == "%PDF" {
		ext = ".pdf"
	} else if strings.Contains(strData, "<?") || strings.Contains(strData, "<request") || strings.Contains(strData, "<afirma") {
		ext = ".xml"
	} else if len(data) > 1000 {
		// Si es grande y no es PDF, asumir XML en este contexto
		ext = ".xml"
	} else {
		// Respaldo para texto/binario pequeño desconocido
		ext = ".txt"
	}

	tmpf, err := os.CreateTemp(os.TempDir(), fmt.Sprintf("autofirma_%s_*%s", safeID, ext))
	if err != nil {
		return "", err
	}
	tmpFile := tmpf.Name()
	if _, err := tmpf.Write(data); err != nil {
		_ = tmpf.Close()
		_ = os.Remove(tmpFile)
		return "", err
	}
	if err := tmpf.Close(); err != nil {
		_ = os.Remove(tmpFile)
		return "", err
	}
	return tmpFile, nil
}

// decryptDES descifra datos con algoritmo DES.
func decryptDES(ciphertext []byte, key []byte) ([]byte, error) {
	// La clave DES debe ser de 8 bytes.
	if len(key) < 8 {
		// Rellenar clave si es demasiado corta
		paddedKey := make([]byte, 8)
		copy(paddedKey, key)
		key = paddedKey
	} else if len(key) > 8 {
		key = key[:8]
	}

	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	// Usar modo ECB (descifrar cada bloque de forma independiente)
	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += block.BlockSize() {
		block.Decrypt(plaintext[i:i+block.BlockSize()], ciphertext[i:i+block.BlockSize()])
	}

	return plaintext, nil
}

// UploadSignature sube los datos firmados al servidor.
func (p *ProtocolState) UploadSignature(signatureB64 string, certB64 string) error {
	// Construir URL de subida
	// Typically: ?op=put&id=FILEID&dat=SIGNATURE_B64
	// Sometimes requires 'cert' param too.

	client := &http.Client{Timeout: 30 * time.Second}

	uploadServlet := p.STServlet
	if uploadServlet == "" {
		// Respaldo solo para flujos legacy donde no se proporciona stservlet.
		uploadServlet = p.RTServlet
		log.Printf("[Protocol] Falta STServlet, usando RTServlet como respaldo para subida: %s", uploadServlet)
	} else {
		log.Printf("[Protocol] Usando STServlet para subida: %s", uploadServlet)
	}
	if err := validateSigningServerURL(uploadServlet, "stservlet/rtservlet"); err != nil {
		return err
	}
	reqURL, err := url.Parse(uploadServlet)
	if err != nil {
		return err
	}

	// Usar POST para datos grandes
	// Java Client (UrlHttpManagerImpl) logic:
	// 1. Toma la URL completa con parámetros (construida en IntermediateServerUtil)
	// 2. Divide la URL en '?'
	// 3. Usa la URL base como URL de petición
	// 4. Query string is used as Body
	//
	// IntermediateServerUtil envía SOLO: op, v, id, dat

	op := "put"
	version := "1_0"

	// Formato payload: CERT_B64 | SIGNATURE_B64
	// If p.Key is present, both parts must be Encrypted (then Base64 encoded)
	// Separator is "|"

	// Decodificar entradas a bytes para procesado uniforme
	certBytes, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return fmt.Errorf("certificado base64 inválido: %v", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("firma base64 inválida: %v", err)
	}

	var payload string
	if p.Key != "" {
		// Cifrado requerido con formato específico de AutoFirma:
		// [PaddingCount].[UrlSafeBase64(EncryptedData)]
		// El padding es ZeroPadding (0x00)

		keyBytes := []byte(p.Key)

		// 2. Cifrar ambos
		encCertVal, err := AutoFirmaEncryptAndFormat(certBytes, keyBytes)
		if err != nil {
			return fmt.Errorf("falló el cifrado del certificado: %v", err)
		}
		encSigVal, err := AutoFirmaEncryptAndFormat(sigBytes, keyBytes)
		if err != nil {
			return fmt.Errorf("falló el cifrado de la firma: %v", err)
		}

		payload = encCertVal + "|" + encSigVal
		log.Printf("[Protocol] Subiendo carga cifrada (Cert|Firma): %s", summarizePayloadForLog(payload))
	} else {
		// Plano: Cert|Sig (AutoFirma suele usar URL Safe Base64 incluso sin cifrado)
		payload = base64.URLEncoding.EncodeToString(certBytes) + "|" + base64.URLEncoding.EncodeToString(sigBytes)
		log.Printf("[Protocol] Subiendo carga en claro (Cert|Firma)")
	}

	sendBody := func(label string, body string, withContentType bool) (bool, string, int, error) {
		u := *reqURL
		u.RawQuery = ""
		resp, err := protocolPostWithTLSFallback(client, u.String(), body, withContentType)
		if err != nil {
			return false, "", 0, fmt.Errorf("%s: fallo de subida: %v", label, err)
		}
		defer resp.Body.Close()

		respBody, _ := io.ReadAll(resp.Body)
		bodyText := strings.TrimSpace(string(respBody))
		log.Printf("[Protocol] %s respuesta de subida estado=%d cuerpo=%q", label, resp.StatusCode, bodyText)

		if resp.StatusCode != 200 {
			return false, bodyText, resp.StatusCode, nil
		}
		if isStorageUploadOKResponse(bodyText) {
			return true, bodyText, resp.StatusCode, nil
		}
		return false, bodyText, resp.StatusCode, nil
	}

	shouldRetryUpload := func(statusCode int, sendErr error) bool {
		if sendErr != nil {
			return true
		}
		return statusCode == 408 || statusCode == 429 || statusCode >= 500
	}

	sendWithRetry := func(label string, body string, withContentType bool) (bool, string, error) {
		const maxAttempts = 3
		var lastBody string
		var lastStatus int
		var lastErr error

		for attempt := 1; attempt <= maxAttempts; attempt++ {
			ok, bodyText, statusCode, sendErr := sendBody(label, body, withContentType)
			if ok {
				return true, bodyText, nil
			}

			lastBody = bodyText
			lastStatus = statusCode
			lastErr = sendErr

			if !shouldRetryUpload(statusCode, sendErr) || attempt == maxAttempts {
				break
			}

			backoff := time.Duration(250*attempt) * time.Millisecond
			log.Printf("[Protocol] %s reintento %d/%d tras fallo transitorio (status=%d err=%v), espera=%s", label, attempt+1, maxAttempts, statusCode, sendErr, backoff)
			time.Sleep(backoff)
		}

		if lastErr != nil {
			return false, lastBody, lastErr
		}
		if lastStatus != 0 && lastStatus != 200 {
			return false, lastBody, fmt.Errorf("%s: error HTTP en subida: %d %s", label, lastStatus, lastBody)
		}
		return false, lastBody, nil
	}

	// Intento 1: cuerpo estilo Java (query-string en bruto, sin URL-encoding de dat).
	bodyA := "op=" + op + "&v=" + version + "&id=" + p.FileID + "&dat=" + payload
	ok, bodyText, err := sendWithRetry("java-style", bodyA, false)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}

	// Intentos de respaldo para servidores con expectativas no estándar.
	legacy := url.Values{}
	for k, v := range p.Params {
		for _, vv := range v {
			legacy.Add(k, vv)
		}
	}
	legacy.Set("op", "put")
	legacy.Set("v", "1_0")
	legacy.Set("id", p.FileID)
	legacy.Set("dat", signatureB64)
	if p.Key != "" {
		legacy.Set("key", p.Key)
	}
	if certB64 != "" {
		legacy.Set("cert", certB64)
	}
	ok, bodyText, err = sendWithRetry("legacy-style", legacy.Encode(), true)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}

	// Último respaldo: mismo estilo legacy pero con request id original.
	if p.RequestID != "" && p.RequestID != p.FileID {
		legacy.Set("id", p.RequestID)
		ok, bodyText, err = sendWithRetry("legacy-style-requestid", legacy.Encode(), true)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
	}

	return fmt.Errorf("la subida al servidor devolvió cuerpo no-OK: %s", bodyText)
}

// UploadCertificate sube solo el certificado seleccionado al servlet de almacenamiento.
// Se usa para flujos de identificación (selectcert) donde no hay firma de documento.
func (p *ProtocolState) UploadCertificate(certB64 string) error {
	client := &http.Client{Timeout: 30 * time.Second}

	uploadServlet := p.STServlet
	if uploadServlet == "" {
		uploadServlet = p.RTServlet
		log.Printf("[Protocol] Falta STServlet, usando RTServlet como respaldo para subida de certificado: %s", uploadServlet)
	} else {
		log.Printf("[Protocol] Usando STServlet para subida de certificado: %s", uploadServlet)
	}
	if err := validateSigningServerURL(uploadServlet, "stservlet/rtservlet"); err != nil {
		return err
	}
	reqURL, err := url.Parse(uploadServlet)
	if err != nil {
		return err
	}

	op := "put"
	version := "1_0"

	certBytes, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return fmt.Errorf("certificado base64 inválido: %v", err)
	}

	var payload string
	if p.Key != "" {
		keyBytes := []byte(p.Key)
		encCertVal, err := AutoFirmaEncryptAndFormat(certBytes, keyBytes)
		if err != nil {
			return fmt.Errorf("falló el cifrado del certificado: %v", err)
		}
		payload = encCertVal
		log.Printf("[Protocol] Subiendo certificado cifrado: %s", summarizePayloadForLog(payload))
	} else {
		payload = base64.URLEncoding.EncodeToString(certBytes)
		log.Printf("[Protocol] Subiendo certificado en claro")
	}

	sendBody := func(label string, body string, withContentType bool) (bool, string, int, error) {
		u := *reqURL
		u.RawQuery = ""
		resp, err := protocolPostWithTLSFallback(client, u.String(), body, withContentType)
		if err != nil {
			return false, "", 0, fmt.Errorf("%s: fallo de subida: %v", label, err)
		}
		defer resp.Body.Close()

		respBody, _ := io.ReadAll(resp.Body)
		bodyText := strings.TrimSpace(string(respBody))
		log.Printf("[Protocol] %s respuesta de subida estado=%d cuerpo=%q", label, resp.StatusCode, bodyText)

		if resp.StatusCode != 200 {
			return false, bodyText, resp.StatusCode, nil
		}
		if isStorageUploadOKResponse(bodyText) {
			return true, bodyText, resp.StatusCode, nil
		}
		return false, bodyText, resp.StatusCode, nil
	}

	bodyA := "op=" + op + "&v=" + version + "&id=" + p.FileID + "&dat=" + payload
	ok, bodyText, statusCode, err := sendBody("java-style-selectcert", bodyA, false)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}

	legacy := url.Values{}
	for k, v := range p.Params {
		for _, vv := range v {
			legacy.Add(k, vv)
		}
	}
	legacy.Set("op", "put")
	legacy.Set("v", "1_0")
	legacy.Set("id", p.FileID)
	legacy.Set("dat", certB64)
	legacy.Set("cert", certB64)
	if p.Key != "" {
		legacy.Set("key", p.Key)
	}
	ok, bodyText, statusCode, err = sendBody("legacy-style-selectcert", legacy.Encode(), true)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	if statusCode != 0 {
		return fmt.Errorf("error HTTP en subida de certificado: %d %s", statusCode, bodyText)
	}
	return fmt.Errorf("la subida de certificado devolvió cuerpo no-OK: %s", bodyText)
}

// UploadResultData sube un resultado textual (base64/urlsafe/etc.) al storage servlet.
// Se utiliza para operaciones batch/selectcert donde no se sube par cert|firma.
func (p *ProtocolState) UploadResultData(dat string) error {
	client := &http.Client{Timeout: 30 * time.Second}

	uploadServlet := strings.TrimSpace(p.STServlet)
	if uploadServlet == "" {
		uploadServlet = strings.TrimSpace(p.RTServlet)
		log.Printf("[Protocol] Falta STServlet, usando RTServlet como respaldo para subida de resultado: %s", uploadServlet)
	} else {
		log.Printf("[Protocol] Usando STServlet para subida de resultado: %s", uploadServlet)
	}
	if uploadServlet == "" {
		return fmt.Errorf("no hay servlet de almacenamiento para subir resultado")
	}
	if err := validateSigningServerURL(uploadServlet, "stservlet/rtservlet"); err != nil {
		return err
	}
	reqURL, err := url.Parse(uploadServlet)
	if err != nil {
		return err
	}

	fileID := strings.TrimSpace(p.FileID)
	if fileID == "" {
		fileID = strings.TrimSpace(p.RequestID)
	}
	if fileID == "" {
		return fmt.Errorf("identificador de solicitud vacío")
	}

	sendBody := func(label string, body string, withContentType bool) (bool, string, int, error) {
		u := *reqURL
		u.RawQuery = ""
		resp, err := protocolPostWithTLSFallback(client, u.String(), body, withContentType)
		if err != nil {
			return false, "", 0, fmt.Errorf("%s: fallo de subida: %v", label, err)
		}
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		bodyText := strings.TrimSpace(string(respBody))
		log.Printf("[Protocol] %s respuesta de subida estado=%d cuerpo=%q", label, resp.StatusCode, bodyText)
		if resp.StatusCode != 200 {
			return false, bodyText, resp.StatusCode, nil
		}
		if isStorageUploadOKResponse(bodyText) {
			return true, bodyText, resp.StatusCode, nil
		}
		return false, bodyText, resp.StatusCode, nil
	}

	javaStyle := url.Values{}
	javaStyle.Set("op", "put")
	javaStyle.Set("v", "1_0")
	javaStyle.Set("id", fileID)
	javaStyle.Set("dat", dat)
	if strings.TrimSpace(p.Key) != "" {
		javaStyle.Set("key", p.Key)
	}
	ok, bodyText, status, err := sendBody("java-style-result", javaStyle.Encode(), true)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}

	legacy := url.Values{}
	for k, v := range p.Params {
		for _, vv := range v {
			legacy.Add(k, vv)
		}
	}
	legacy.Set("op", "put")
	legacy.Set("v", "1_0")
	legacy.Set("id", fileID)
	legacy.Set("dat", dat)
	ok, bodyText, status, err = sendBody("legacy-style-result", legacy.Encode(), true)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	if status != 0 {
		return fmt.Errorf("error HTTP en subida de resultado: %d %s", status, bodyText)
	}
	return fmt.Errorf("la subida de resultado devolvió cuerpo no-OK: %s", bodyText)
}

func summarizePayloadForLog(payload string) string {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return "payload[vacio]"
	}
	if len(payload) <= 24 {
		return "payload[" + payload + "]"
	}
	return fmt.Sprintf("payload[%s...%s len=%d]", payload[:12], payload[len(payload)-8:], len(payload))
}

func isStorageUploadOKResponse(bodyText string) bool {
	normalized := strings.TrimSpace(bodyText)
	normalized = strings.Trim(normalized, "\"'")
	upper := strings.ToUpper(normalized)
	switch upper {
	case "OK", "SAVE_OK", "1", "1)":
		return true
	}
	decoders := []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	}
	for _, decode := range decoders {
		decoded, err := decode(normalized)
		if err != nil {
			continue
		}
		decodedTxt := strings.TrimSpace(string(decoded))
		decodedTxt = strings.Trim(decodedTxt, "\"'")
		switch strings.ToUpper(decodedTxt) {
		case "OK", "SAVE_OK", "1", "1)":
			return true
		}
	}
	return false
}

// SendWaitSignal envía marcador WAIT compatible con Java al storage servlet.
func (p *ProtocolState) SendWaitSignal() error {
	if p == nil {
		return fmt.Errorf("estado de protocolo nulo")
	}
	if p.STServlet == "" {
		return fmt.Errorf("servlet de almacenamiento vacío")
	}
	if err := validateSigningServerURL(p.STServlet, "stservlet"); err != nil {
		return err
	}
	if p.RequestID == "" {
		return fmt.Errorf("identificador de solicitud vacío")
	}

	client := &http.Client{Timeout: 15 * time.Second}
	reqURL, err := url.Parse(p.STServlet)
	if err != nil {
		return err
	}

	postBody := "op=put&v=1_0&id=" + p.RequestID + "&dat=#WAIT"
	reqURL.RawQuery = ""
	resp, err := protocolPostWithTLSFallback(client, reqURL.String(), postBody, true)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyText := strings.TrimSpace(string(body))
	log.Printf("[Protocol] Respuesta WAIT estado=%d cuerpo=%q", resp.StatusCode, bodyText)

	if resp.StatusCode != 200 {
		return fmt.Errorf("falló WAIT: %d %s", resp.StatusCode, bodyText)
	}
	if !isStorageUploadOKResponse(bodyText) {
		return fmt.Errorf("WAIT devolvió cuerpo no OK: %s", bodyText)
	}
	return nil
}

func protocolPostWithTLSFallback(client *http.Client, rawURL string, body string, withContentType bool) (*http.Response, error) {
	buildReq := func() (*http.Request, error) {
		req, err := http.NewRequest("POST", rawURL, strings.NewReader(body))
		if err != nil {
			return nil, err
		}
		if withContentType {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		req.Header.Set("User-Agent", "AutoFirma/1.6.5")
		req.Header.Set("Accept", "*/*")
		return req, nil
	}

	req, err := buildReq()
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err == nil {
		return resp, nil
	}
	if !isTLSUnknownAuthorityError(err) {
		return nil, err
	}

	timeout := 30 * time.Second
	if client != nil && client.Timeout > 0 {
		timeout = client.Timeout
	}
	fallbackClient, loaded, fbErr := buildBatchHTTPFallbackClient(timeout, rawURL)
	if fbErr == nil && loaded > 0 {
		log.Printf("[Protocol] fallback TLS activado en subida (unknown authority): certificados extra cargados=%d", loaded)
		req2, reqErr := buildReq()
		if reqErr != nil {
			return nil, reqErr
		}
		resp2, err2 := fallbackClient.Do(req2)
		if err2 == nil {
			return resp2, nil
		}
		err = err2
	}

	if host, allowed := shouldUseBatchInsecureTLSException(rawURL); allowed {
		log.Printf("[Protocol] AVISO SEGURIDAD: usando excepción TLS por dominio=%s en subida.", host)
		insecureClient := buildBatchHTTPInsecureExceptionClient(timeout, host)
		req3, reqErr := buildReq()
		if reqErr != nil {
			return nil, reqErr
		}
		resp3, err3 := insecureClient.Do(req3)
		if err3 == nil {
			return resp3, nil
		}
		err = err3
	}

	return nil, err
}

// HandleProtocolInit inicia el flujo desde la UI.
func (ui *UI) HandleProtocolInit(uriString string) {
	ui.StatusMsg = "Iniciando modo protocolo web..."
	ui.Window.Invalidate()

	state, err := ParseProtocolURI(uriString)
	if err != nil {
		ui.StatusMsg = "Error protocolo: " + err.Error()
		ui.Window.Invalidate()
		return
	}

	ui.Protocol = state
	log.Printf("[Protocol] Solicitud web recibida: %s", protocolRequestSummaryES(state))
	ui.updateSessionDiagnostics("afirma-protocol", state.Action, getProtocolSessionID(state), normalizeProtocolFormat(state.SignFormat), "protocol_init")

	// Flujo de identificación: solo selección de certificado (sin fichero PDF).
	if normalizeProtocolAction(state.Action) == "selectcert" {
		log.Printf("[Protocol] Flujo de identificación detectado (sin documento): %s", protocolRequestSummaryES(state))
		ui.StatusMsg = "Solicitud de identificación recibida. Seleccione su certificado."
		ui.Window.Invalidate()
		go ui.handleProtocolSelectCert(state)
		return
	}
	// Flujo batch: procesar lote y devolver resultado sin pedir selección de PDF manual.
	if normalizeProtocolAction(state.Action) == "batch" {
		log.Printf("[Protocol] Flujo batch detectado (sin selección manual de PDF): %s", protocolRequestSummaryES(state))
		ui.StatusMsg = "Solicitud de lote recibida. Seleccione certificado y pulse 'Procesar lote'."
		ui.updateSessionDiagnostics("afirma-protocol", state.Action, getProtocolSessionID(state), "-", "batch_waiting_cert")
		ui.Window.Invalidate()
		return
	}

	ui.StatusMsg = "Descargando documento del servidor..."
	ui.Window.Invalidate()

	go func() {
		path, err := state.DownloadFile()
		if err != nil {
			ui.StatusMsg = "Error descarga: " + err.Error()
			ui.Window.Invalidate()
			return
		}

		if path != "" {
			// Comprobar si el archivo descargado es una solicitud XML de AutoFirma
			content, err := os.ReadFile(path)
			if err == nil && strings.HasPrefix(string(content), "<sign>") {
				log.Printf("[Protocol] Solicitud XML de AutoFirma detectada, analizando...")
				// Parsear XML para extraer datos reales y actualizar estado de protocolo (stservlet)
				actualData, format, err := parseAutoFirmaXML(content, ui.Protocol)
				if err != nil {
					log.Printf("[Protocol] Falló el análisis de XML: %v", err)
					ui.StatusMsg = "Error parseando XML: " + err.Error()
					ui.Window.Invalidate()
					return
				}
				log.Printf("[Protocol] XML analizado correctamente, formato=%s, tamaño de datos=%d", format, len(actualData))

				// Guardar formato en estado de protocolo
				ui.Protocol.SignFormat = format

				// Guardar datos reales en un archivo nuevo
				ext := ".bin"
				if format == "PAdES" {
					ext = ".pdf"
				} else if format == "XAdES" {
					ext = ".xml"
				}

				tmpDataFile, err := os.CreateTemp(os.TempDir(), "autofirma_xml_data_*"+ext)
				if err != nil {
					ui.StatusMsg = "Error guardando datos: " + err.Error()
					ui.Window.Invalidate()
					return
				}
				actualPath := tmpDataFile.Name()
				if _, err := tmpDataFile.Write(actualData); err != nil {
					_ = tmpDataFile.Close()
					_ = os.Remove(actualPath)
					ui.StatusMsg = "Error guardando datos: " + err.Error()
					ui.Window.Invalidate()
					return
				}
				if err := tmpDataFile.Close(); err != nil {
					_ = os.Remove(actualPath)
					ui.StatusMsg = "Error guardando datos: " + err.Error()
					ui.Window.Invalidate()
					return
				}

				path = actualPath
				log.Printf("[Protocol] Datos %s extraídos de solicitud XML (%d bytes)", format, len(actualData))
			}
			ui.InputFile.SetText(path)
			ui.StatusMsg = "Documento descargado. Seleccione certificado y firme."
			ui.updateSessionDiagnostics("afirma-protocol", state.Action, getProtocolSessionID(state), normalizeProtocolFormat(ui.Protocol.SignFormat), "file_ready")
		} else {
			// No se descargó archivo (flujo local)
			log.Println("[Protocol] No se descargó documento. Esperando selección manual.")
			ui.StatusMsg = "Iniciado modo firma local web. Seleccione archivo y certificado."
			ui.updateSessionDiagnostics("afirma-protocol", state.Action, getProtocolSessionID(state), normalizeProtocolFormat(ui.Protocol.SignFormat), "local_waiting_file")
		}

		ui.Mode = 0 // Asegurar modo Firma
		ui.Window.Invalidate()
	}()
}

func (ui *UI) handleProtocolSelectCert(state *ProtocolState) {
	if state == nil {
		ui.StatusMsg = "Error protocolo: estado inválido en selectcert."
		ui.Window.Invalidate()
		return
	}

	certs, err := loadCertificatesForState(state)
	if err != nil {
		ui.StatusMsg = "Error cargando certificados para identificación: " + err.Error()
		ui.updateSessionDiagnostics("afirma-protocol", state.Action, getProtocolSessionID(state), "-", "selectcert_error_load")
		ui.Window.Invalidate()
		return
	}
	filtered, _ := filterSelectCertByDefaultStore(certs, state)
	if len(filtered) == 0 {
		filtered = certs
	}
	storePref := resolveDefaultKeyStorePreference(state)
	if strings.TrimSpace(storePref) != "" {
		log.Printf("[Protocol] SelectCert: almacén solicitado=%s certificados_mostrados=%d total_detectados=%d", storePref, len(filtered), len(certs))
	}
	if len(filtered) == 0 {
		ui.StatusMsg = "No hay certificados disponibles para identificación."
		ui.updateSessionDiagnostics("afirma-protocol", state.Action, getProtocolSessionID(state), "-", "selectcert_empty")
		ui.Window.Invalidate()
		return
	}

	chosen, canceled, err := protocolSelectCertDialog(filtered)
	if canceled {
		ui.StatusMsg = "Selección de certificado cancelada."
		ui.updateSessionDiagnostics("afirma-protocol", state.Action, getProtocolSessionID(state), "-", "selectcert_cancel")
		ui.Window.Invalidate()
		return
	}
	if err != nil {
		ui.StatusMsg = "Error en selector de certificado: " + err.Error()
		ui.updateSessionDiagnostics("afirma-protocol", state.Action, getProtocolSessionID(state), "-", "selectcert_error_dialog")
		ui.Window.Invalidate()
		return
	}
	if chosen < 0 || chosen >= len(filtered) || len(filtered[chosen].Content) == 0 {
		ui.StatusMsg = "Selección de certificado inválida."
		ui.updateSessionDiagnostics("afirma-protocol", state.Action, getProtocolSessionID(state), "-", "selectcert_invalid")
		ui.Window.Invalidate()
		return
	}

	// Reflejar selección en la UI principal si coincide con lista cargada.
	for idx := range ui.Certs {
		if ui.Certs[idx].ID == filtered[chosen].ID {
			ui.SelectedCert = idx
			break
		}
	}

	certB64 := base64.StdEncoding.EncodeToString(filtered[chosen].Content)
	if strings.TrimSpace(state.STServlet) != "" || strings.TrimSpace(state.RTServlet) != "" {
		if err := state.UploadCertificate(certB64); err != nil {
			ui.StatusMsg = "Error enviando certificado a la web: " + err.Error()
			ui.updateSessionDiagnostics("afirma-protocol", state.Action, getProtocolSessionID(state), "-", "selectcert_error_upload")
			ui.Window.Invalidate()
			return
		}
	}

	ui.StatusMsg = "Certificado de identificación enviado correctamente."
	ui.updateSessionDiagnostics("afirma-protocol", state.Action, getProtocolSessionID(state), "-", "selectcert_ok")
	ui.ShouldClose = true
	ui.Window.Invalidate()
}

func (ui *UI) handleProtocolBatch(state *ProtocolState) {
	if state == nil {
		ui.StatusMsg = "Error protocolo: estado inválido en batch."
		ui.Window.Invalidate()
		return
	}
	if ui.IsSigning {
		ui.StatusMsg = "Ya hay una operación en curso. Espere a que termine."
		ui.Window.Invalidate()
		return
	}
	ui.IsSigning = true
	ui.Window.Invalidate()
	defer func() {
		ui.IsSigning = false
		ui.Window.Invalidate()
	}()
	srv := &WebSocketServer{ui: ui}
	result := strings.TrimSpace(srv.processBatchRequest(state))
	upper := strings.ToUpper(result)
	if strings.HasPrefix(upper, "SAF_") || strings.HasPrefix(upper, "ERR-") || strings.HasPrefix(upper, "ERROR_") {
		hint := "Reintenta el lote y revisa la conectividad con el servicio remoto."
		lower := strings.ToLower(result)
		if strings.Contains(lower, "saf_26") && strings.Contains(lower, "tls") {
			hint = "La app no confía en la cadena TLS del servicio remoto. Usa 'Diagnóstico TLS del servicio' y, si falta cadena, 'Añadir confianza TLS (.crt/.cer)'."
		} else if strings.Contains(lower, "saf_26") && strings.Contains(lower, "dns") {
			hint = "Revisa DNS/red corporativa y vuelve a intentar."
		}
		ui.setLastError("ERR_BATCH_REMOTE", "remoto", "batch", fmt.Errorf("%s", result), hint)
		ui.StatusMsg = "Error procesando lote: " + result
		ui.updateSessionDiagnostics("afirma-protocol", state.Action, getProtocolSessionID(state), "-", "batch_error")
		ui.Window.Invalidate()
		return
	}

	if strings.TrimSpace(state.STServlet) != "" || strings.TrimSpace(state.RTServlet) != "" {
		if err := state.UploadResultData(result); err != nil {
			ui.StatusMsg = "Lote procesado, pero falló la subida de resultado: " + err.Error()
			ui.setLastError("ERR_BATCH_UPLOAD", "subida", "batch", err, "Reintenta la operación y revisa STServlet/RTServlet del servicio remoto.")
			ui.updateSessionDiagnostics("afirma-protocol", state.Action, getProtocolSessionID(state), "-", "batch_error_upload")
			ui.Window.Invalidate()
			return
		}
	}

	ui.clearLastError()
	ui.StatusMsg = "Lote procesado y resultado enviado correctamente."
	ui.updateSessionDiagnostics("afirma-protocol", state.Action, getProtocolSessionID(state), "-", "batch_ok")
	ui.ShouldClose = true
	ui.Window.Invalidate()
}

// parseAutoFirmaXML extrae datos reales a firmar y actualiza ProtocolState con parámetros del XML.
func parseAutoFirmaXML(xmlData []byte, p *ProtocolState) ([]byte, string, error) {
	var root xmlRoot
	// Gestionar decodificación XML
	if err := xml.Unmarshal(xmlData, &root); err != nil {
		// Respaldo para XML no estricto o si falla Unmarshal.
		// Si hiciera falta, se intentaría parseo manual, pero debería ser XML estándar.
		return nil, "", fmt.Errorf("falló XML Unmarshal: %v", err)
	}

	params := make(map[string]string)
	for _, e := range root.Entries {
		// Java: URLDecoder.decode(value, DEFAULT_URL_ENCODING)
		val, err := url.QueryUnescape(e.Value)
		if err != nil {
			log.Printf("[Protocol] Aviso: no se pudo desescapar valor para clave %s: %v", e.Key, err)
			val = e.Value
		}
		params[e.Key] = val

		// Actualizar mapa de parámetros del protocolo
		p.Params.Set(e.Key, val)
	}

	// Crítico: actualizar STServlet si está presente
	if st := params["stservlet"]; st != "" {
		if err := validateSigningServerURL(st, "stservlet"); err != nil {
			return nil, "", err
		}
		p.STServlet = st
		log.Printf("[Protocol] STServlet actualizado desde XML: %s", st)
	}

	// El id de subida viene del id de sesión XML cuando está presente.
	if id := params["id"]; id != "" {
		p.FileID = id
		log.Printf("[Protocol] Id de sesión actualizado desde XML (id de subida): %s", id)
	}

	// Crítico: actualizar Key si está presente
	if k := params["key"]; k != "" {
		p.Key = k
	}

	// Extraer datos ('dat')
	datB64, ok := params["dat"]
	if !ok {
		return nil, "", fmt.Errorf("no se encontró parámetro 'dat' en el manifiesto XML")
	}

	// Limpiar Base64 (comportamiento estándar Java)
	datB64 = strings.TrimSpace(datB64)

	// Decodificar Base64
	// Probar primero estándar y luego URL-safe
	data, err := base64.StdEncoding.DecodeString(datB64)
	if err != nil {
		// Probar codificación URL
		data, err = base64.URLEncoding.DecodeString(datB64)
		if err != nil {
			return nil, "", fmt.Errorf("falló la decodificación de 'dat' (Base64): %v", err)
		}
	}

	format := params["format"]
	if format == "" {
		format = "CAdES" // Por defecto
	}

	return data, format, nil
}

// encryptDES cifra datos con DES (modo ECB). La entrada debe venir ya padded.
func encryptDES(plaintext []byte, key []byte) ([]byte, error) {
	// La clave DES debe ser de 8 bytes
	if len(key) < 8 {
		paddedKey := make([]byte, 8)
		copy(paddedKey, key)
		key = paddedKey
	} else if len(key) > 8 {
		key = key[:8]
	}

	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Se asume que plaintext ya viene padded al tamaño de bloque
	if len(plaintext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("plaintext is not a multiple of the block size")
	}

	ciphertext := make([]byte, len(plaintext))
	// Modo ECB
	bs := block.BlockSize()
	for i := 0; i < len(plaintext); i += bs {
		block.Encrypt(ciphertext[i:i+bs], plaintext[i:i+bs])
	}

	return ciphertext, nil
}

// AutoFirmaEncryptAndFormat cifra y formatea datos según patrón Java de AutoFirma: [PaddingCount].[UrlSafeBase64(EncryptedData)].
func AutoFirmaEncryptAndFormat(data []byte, keyBytes []byte) (string, error) {
	padLen := (8 - (len(data) % 8)) % 8
	// Rellenar con ceros (comportamiento estándar AutoFirma Java para DES ECB)
	if padLen > 0 {
		padding := make([]byte, padLen)
		data = append(data, padding...)
	}

	encBytes, err := encryptDES(data, keyBytes)
	if err != nil {
		return "", err
	}

	// Usar URL Safe Base64 CON PADDING (patrón Java de AutoFirma)
	b64 := base64.URLEncoding.EncodeToString(encBytes)
	return fmt.Sprintf("%d.%s", padLen, b64), nil
}
