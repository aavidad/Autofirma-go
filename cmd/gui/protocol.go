// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	// Added for padding
	"crypto/des"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// XML structures for Manifest Parsing
type xmlEntry struct {
	Key   string `xml:"k,attr"`
	Value string `xml:"v,attr"`
}
type xmlRoot struct {
	XMLName xml.Name
	Entries []xmlEntry `xml:"e"`
}

type ProtocolState struct {
	IsActive   bool
	RTServlet  string
	STServlet  string // Dedicated Storage URL
	FileID     string
	RequestID  string // Original URI fileid (used by WAIT loop)
	Key        string
	Action     string // "sign"
	SourceURL  string
	Params     url.Values // Store all params
	SignFormat string     // Format from XML: "CAdES", "PAdES", "XAdES"
}

// ParseProtocolURI parses "afirma://..." URI
func ParseProtocolURI(uriString string) (*ProtocolState, error) {
	// Remove "afirma://" prefix to parse as URL if needed, or just use url.Parse
	u, err := url.Parse(uriString)
	if err != nil {
		return nil, err
	}

	q := u.Query()

	state := &ProtocolState{
		IsActive:  true,
		SourceURL: uriString,
		Action:    u.Host,
		Params:    q, // Keep all params
	}

	state.FileID = q.Get("fileid")
	state.RequestID = state.FileID
	state.Key = q.Get("key")
	state.RTServlet = q.Get("rtservlet")

	if state.RTServlet == "" && state.FileID == "" {
		return nil, fmt.Errorf("missing required parameters (rtservlet, fileid)")
	}

	if state.RTServlet == "" {
		// Log warning but proceed, some flows might not strictly need it if data is otherwise available
		// or will fail later at DownloadFile if really needed.
		log.Printf("[Protocol] Warning: 'rtservlet' parameter is missing. Download might fail if implicit URL is not found.")
	}

	return state, nil
}

// DownloadFile retrieves the file to sign
func (p *ProtocolState) DownloadFile() (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	// Helper to attempt download
	attempt := func(method string) (string, []byte, error) {
		reqURL, err := url.Parse(p.RTServlet)
		if err != nil {
			return "", nil, err
		}

		// Prepare params: Strictly standard ones (like Java client)
		data := url.Values{}

		// Enforce/Overwrite critical ops
		data.Set("op", "get")
		data.Set("v", "1_0")
		data.Set("id", p.FileID)

		// NOTE: Java client (IntermediateServerUtil) does NOT send 'key' or extra params
		// in the retrieveData request. It only sends op, v, and id.
		// The key is used locally for decryption only.

		var req *http.Request
		if method == "GET" {
			reqURL.RawQuery = data.Encode() // Replaces any existing query
			req, err = http.NewRequest("GET", reqURL.String(), nil)
			log.Printf("[Protocol] GET URL: %s", reqURL.String()) // Log full URL
		} else {
			// POST (Fallback if GET fails/not allowed)
			// For POST, Java client strips query from URL and puts it in Body.
			reqURL.RawQuery = ""
			encodedData := data.Encode()
			req, err = http.NewRequest("POST", reqURL.String(), strings.NewReader(encodedData))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			log.Printf("[Protocol] POST Data: %s", encodedData) // Log body
		}

		if err != nil {
			return "", nil, err
		}

		// Headers mimicking AutoFirma
		req.Header.Set("User-Agent", "AutoFirma/1.6.5") // Use a standard version
		req.Header.Set("Accept", "*/*")

		log.Printf("[Protocol] Attempting %s %s", method, p.RTServlet)

		resp, err := client.Do(req)
		if err != nil {
			return "", nil, err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", nil, err
		}

		log.Printf("[Protocol] Status: %d, ContentLength: %d", resp.StatusCode, len(body))

		if resp.StatusCode != 200 {
			return "", body, fmt.Errorf("server error %d", resp.StatusCode)
		}

		return "", body, nil
	}

	// Try GET
	_, body, err := attempt("GET")

	// Check if valid (size > 100 etc or not starting with ERR-)
	if err == nil && len(body) > 100 { // Reduced threshold slightly
		if strings.HasPrefix(strings.ToLower(string(body)), "err-") {
			log.Printf("[Protocol] Server returned error content: %s", string(body))
		} else {
			// Success with GET
			return saveTemp(body, p.FileID, p.Key)
		}
	}

	if len(body) < 500 {
		log.Printf("[Protocol] GET response too small: %s", string(body))
	}

	// Try POST as fallback
	log.Println("[Protocol] GET failed or small content. Trying POST...")
	_, bodyPost, errPost := attempt("POST")
	if errPost == nil && len(bodyPost) > 200 {
		return saveTemp(bodyPost, p.FileID, p.Key)
	}

	// Failed
	if len(bodyPost) < 500 {
		log.Printf("[Protocol] POST response: %s", string(bodyPost))
		return "", fmt.Errorf("descarga fallida. El servidor devolvió: %s", string(bodyPost))
	}

	return "", fmt.Errorf("no se pudo descargar el documento (GET y POST fallaron)")
}

func saveTemp(data []byte, fileID string, key string) (string, error) {
	// Use sanitized fileID for name
	safeID := filepath.Base(fileID)
	if safeID == "" || safeID == "." {
		safeID = "autofirma_doc"
	}

	// AutoFirma encrypts data in format: PADDING.ENCRYPTED_BASE64
	// First, try to decrypt if we have a key
	if key != "" {
		dataStr := string(data)

		// Check if it has the PADDING.DATA format
		if strings.Contains(dataStr, ".") {
			parts := strings.SplitN(dataStr, ".", 2)
			if len(parts) == 2 {
				padding, err := strconv.Atoi(parts[0])
				if err == nil {
					// Convert URL-safe Base64 to standard
					b64Data := strings.ReplaceAll(parts[1], "-", "+")
					b64Data = strings.ReplaceAll(b64Data, "_", "/")

					// Decode Base64
					encrypted, err := base64.StdEncoding.DecodeString(b64Data)
					if err == nil {
						// Decrypt with DES
						decrypted, err := decryptDES(encrypted, []byte(key))
						if err == nil {
							// Remove padding
							if padding > 0 && padding < len(decrypted) {
								decrypted = decrypted[:len(decrypted)-padding]
							}
							log.Printf("[Protocol] Successfully decrypted data (padding=%d, size=%d)", padding, len(decrypted))
							data = decrypted
						} else {
							log.Printf("[Protocol] DES decryption failed: %v", err)
						}
					}
				}
			}
		}
	}

	// Try Base64 Decoding (Robust)
	decoded := false
	inputs := []string{string(data)}

	// If it contains a dot, it might be [VERSION].[DATA]
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
		// Clean whitespace
		input = strings.TrimSpace(input)

		// Try various decoders
		decoders := []*base64.Encoding{
			base64.StdEncoding,
			base64.URLEncoding,
			base64.RawURLEncoding,
			base64.RawStdEncoding,
		}

		for _, enc := range decoders {
			decodedBytes, err := enc.DecodeString(input)
			if err == nil && len(decodedBytes) > 0 {
				// Check header
				strDecoded := string(decodedBytes)
				isPDF := len(decodedBytes) > 4 && string(decodedBytes[:4]) == "%PDF"
				isXML := strings.Contains(strDecoded, "<?xml") || strings.Contains(strDecoded, "<afirma") || strings.Contains(strDecoded, "<request")

				if isPDF || isXML {
					debugLen := 10
					if len(decodedBytes) < 10 {
						debugLen = len(decodedBytes)
					}
					log.Printf("[Protocol] Successfully decoded Base64. Header: %x", decodedBytes[:debugLen])
					data = decodedBytes
					decoded = true
					break
				}
			}
		}
	}

	// Detect extension
	ext := ".pdf" // Default
	strData := string(data)

	// Debug: Log first 50 bytes to see what we really got
	debugLen := 50
	if len(data) < 50 {
		debugLen = len(data)
	}
	log.Printf("[Protocol] File Header detected: %x (string: %q)", data[:debugLen], string(data[:debugLen]))

	if len(data) > 4 && string(data[:4]) == "%PDF" {
		ext = ".pdf"
	} else if strings.Contains(strData, "<?") || strings.Contains(strData, "<request") || strings.Contains(strData, "<afirma") {
		ext = ".xml"
	} else if len(data) > 1000 {
		// If it's big and not a PDF, assume XML in this context
		ext = ".xml"
	} else {
		// Fallback for unknown small text/binary
		ext = ".txt"
	}

	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("autofirma_%s%s", safeID, ext))
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return "", err
	}
	return tmpFile, nil
}

// decryptDES decrypts data using DES algorithm
func decryptDES(ciphertext []byte, key []byte) ([]byte, error) {
	// DES key must be 8 bytes
	if len(key) < 8 {
		// Pad key if too short
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

	// Use ECB mode (decrypt each block independently)
	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += block.BlockSize() {
		block.Decrypt(plaintext[i:i+block.BlockSize()], ciphertext[i:i+block.BlockSize()])
	}

	return plaintext, nil
}

// UploadSignature uploads the signed data back
func (p *ProtocolState) UploadSignature(signatureB64 string, certB64 string) error {
	// Construct upload URL
	// Typically: ?op=put&id=FILEID&dat=SIGNATURE_B64
	// Sometimes requires 'cert' param too.

	client := &http.Client{Timeout: 30 * time.Second}

	uploadServlet := p.STServlet
	if uploadServlet == "" {
		// Fallback only for legacy flows where stservlet is not provided.
		uploadServlet = p.RTServlet
		log.Printf("[Protocol] STServlet missing, falling back to RTServlet for upload: %s", uploadServlet)
	} else {
		log.Printf("[Protocol] Using STServlet for upload: %s", uploadServlet)
	}
	reqURL, err := url.Parse(uploadServlet)
	if err != nil {
		return err
	}

	// Use POST for large data
	// Java Client (UrlHttpManagerImpl) logic:
	// 1. Takes the full URL with params (constructed in IntermediateServerUtil)
	// 2. Splits URL at '?'
	// 3. Base URL is used as request URL
	// 4. Query string is used as Body
	//
	// IntermediateServerUtil sends ONLY: op, v, id, dat

	op := "put"
	version := "1_0"

	// Format payload: CERT_B64 | SIGNATURE_B64
	// If p.Key is present, both parts must be Encrypted (then Base64 encoded)
	// Separator is "|"

	var payload string
	if p.Key != "" {
		// Encryption required with specific AutoFirma format:
		// [PaddingCount].[UrlSafeBase64(EncryptedData)]
		// Padding is ZeroPadding (0x00)

		keyBytes := []byte(p.Key)

		// Helper to encrypt and format
		encryptAndFormat := func(data []byte) (string, error) {
			padLen := (8 - (len(data) % 8)) % 8
			// Pad with Zeros
			if padLen > 0 {
				padding := make([]byte, padLen)
				data = append(data, padding...)
			}

			encBytes, err := encryptDES(data, keyBytes)
			if err != nil {
				return "", err
			}

			// Use URL Safe Base64
			b64 := base64.URLEncoding.EncodeToString(encBytes)
			return fmt.Sprintf("%d.%s", padLen, b64), nil
		}

		// 1. Decode inputs to bytes
		certBytes, err := base64.StdEncoding.DecodeString(certB64)
		if err != nil {
			return fmt.Errorf("invalid cert base64: %v", err)
		}
		sigBytes, err := base64.StdEncoding.DecodeString(signatureB64)
		if err != nil {
			return fmt.Errorf("invalid sig base64: %v", err)
		}

		// 2. Encrypt both
		encCertVal, err := encryptAndFormat(certBytes)
		if err != nil {
			return fmt.Errorf("encrypt cert failed: %v", err)
		}
		encSigVal, err := encryptAndFormat(sigBytes)
		if err != nil {
			return fmt.Errorf("encrypt sig failed: %v", err)
		}

		payload = encCertVal + "|" + encSigVal
		log.Printf("[Protocol] Uploading Encrypted payload (Cert|Sig): %s", payload)
	} else {
		// Plain: Cert|Sig
		// Note: Java might use URL Safe Base64 here too?
		// NativeSignDataProcessor: dataToSend.append(Base64.encode(certEncoded, true)); (True = URL Safe usually)
		// We safely assume URL Safe is better, or Standard.
		// But UploadSignature mainly hit when Key is present (DGSFP uses keys).
		// If no key, we keep as is or switch to URL Safe?
		// Let's keep Standard for now as non-encrypted flows might differ,
		// but given the Encryption path uses URL Safe, likely everything does.
		// However, I don't want to break non-encrypted if it wasn't broken.
		payload = certB64 + "|" + signatureB64
		log.Printf("[Protocol] Uploading Plain payload (Cert|Sig)")
	}

	sendBody := func(label string, body string, withContentType bool) (bool, string, error) {
		u := *reqURL
		u.RawQuery = ""
		req, err := http.NewRequest("POST", u.String(), strings.NewReader(body))
		if err != nil {
			return false, "", err
		}
		if withContentType {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		req.Header.Set("User-Agent", "AutoFirma/1.6.5")
		req.Header.Set("Accept", "*/*")

		resp, err := client.Do(req)
		if err != nil {
			return false, "", fmt.Errorf("%s upload failed: %v", label, err)
		}
		defer resp.Body.Close()

		respBody, _ := io.ReadAll(resp.Body)
		bodyText := strings.TrimSpace(string(respBody))
		log.Printf("[Protocol] %s upload response status=%d body=%q", label, resp.StatusCode, bodyText)

		if resp.StatusCode != 200 {
			return false, bodyText, fmt.Errorf("%s upload HTTP error: %d %s", label, resp.StatusCode, bodyText)
		}
		if strings.EqualFold(bodyText, "OK") || strings.Contains(strings.ToUpper(bodyText), "OK") {
			return true, bodyText, nil
		}
		return false, bodyText, nil
	}

	// Attempt 1: Java-style body (raw query-string body, without URL-encoding dat).
	bodyA := "op=" + op + "&v=" + version + "&id=" + p.FileID + "&dat=" + payload
	ok, bodyText, err := sendBody("java-style", bodyA, false)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}

	// Fallback attempts for servers with non-standard expectations.
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
	ok, bodyText, err = sendBody("legacy-style", legacy.Encode(), true)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}

	// Last fallback: same legacy style but with original request id.
	if p.RequestID != "" && p.RequestID != p.FileID {
		legacy.Set("id", p.RequestID)
		ok, bodyText, err = sendBody("legacy-style-requestid", legacy.Encode(), true)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
	}

	return fmt.Errorf("server upload returned non-OK body: %s", bodyText)
}

// SendWaitSignal sends Java-compatible active wait marker to storage servlet.
func (p *ProtocolState) SendWaitSignal() error {
	if p == nil {
		return fmt.Errorf("protocol state is nil")
	}
	if p.STServlet == "" {
		return fmt.Errorf("storage servlet is empty")
	}
	if p.RequestID == "" {
		return fmt.Errorf("request id is empty")
	}

	client := &http.Client{Timeout: 15 * time.Second}
	reqURL, err := url.Parse(p.STServlet)
	if err != nil {
		return err
	}

	postBody := "op=put&v=1_0&id=" + p.RequestID + "&dat=#WAIT"
	reqURL.RawQuery = ""
	req, err := http.NewRequest("POST", reqURL.String(), strings.NewReader(postBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "AutoFirma/1.6.5")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyText := strings.TrimSpace(string(body))
	log.Printf("[Protocol] WAIT response status=%d body=%q", resp.StatusCode, bodyText)

	if resp.StatusCode != 200 {
		return fmt.Errorf("wait failed: %d %s", resp.StatusCode, bodyText)
	}
	if !strings.EqualFold(bodyText, "OK") && !strings.Contains(strings.ToUpper(bodyText), "OK") {
		return fmt.Errorf("wait non-OK body: %s", bodyText)
	}
	return nil
}

// HandleProtocolInit initiates the flow from UI
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
	ui.StatusMsg = "Descargando documento del servidor..."
	ui.Window.Invalidate()

	go func() {
		path, err := state.DownloadFile()
		if err != nil {
			ui.StatusMsg = "Error descarga: " + err.Error()
			ui.Window.Invalidate()
			return
		}

		// Check if the downloaded file is an AutoFirma XML request
		content, err := os.ReadFile(path)
		if err == nil && strings.HasPrefix(string(content), "<sign>") {
			log.Printf("[Protocol] Detected AutoFirma XML request, parsing...")
			// Parse XML to extract actual data AND update Protocol State (stservlet)
			actualData, format, err := parseAutoFirmaXML(content, ui.Protocol)
			if err != nil {
				log.Printf("[Protocol] XML parsing failed: %v", err)
				ui.StatusMsg = "Error parseando XML: " + err.Error()
				ui.Window.Invalidate()
				return
			}
			log.Printf("[Protocol] XML parsed successfully, format=%s, data size=%d", format, len(actualData))

			// Store the format in protocol state
			ui.Protocol.SignFormat = format

			// Save the actual data to a new file
			ext := ".bin"
			if format == "PAdES" {
				ext = ".pdf"
			} else if format == "XAdES" {
				ext = ".xml"
			}

			actualPath := strings.TrimSuffix(path, filepath.Ext(path)) + "_data" + ext
			if err := os.WriteFile(actualPath, actualData, 0644); err != nil {
				ui.StatusMsg = "Error guardando datos: " + err.Error()
				ui.Window.Invalidate()
				return
			}

			path = actualPath
			log.Printf("[Protocol] Extracted %s data from XML request (%d bytes)", format, len(actualData))
		}

		ui.InputFile.SetText(path)
		ui.StatusMsg = "Documento descargado. Seleccione certificado y firme."
		ui.Mode = 0 // Ensure Sign mode
		ui.Window.Invalidate()
	}()
}

// parseAutoFirmaXML extracts the actual data to sign and updates ProtocolState with params from XML
func parseAutoFirmaXML(xmlData []byte, p *ProtocolState) ([]byte, string, error) {
	var root xmlRoot
	// Handle XML decoding
	if err := xml.Unmarshal(xmlData, &root); err != nil {
		// Fallback for non-strict XML or if Unmarshal fails?
		// Try manual parsing if needed, but XML should be standard.
		return nil, "", fmt.Errorf("XML Unmarshal failed: %v", err)
	}

	params := make(map[string]string)
	for _, e := range root.Entries {
		// Java: URLDecoder.decode(value, DEFAULT_URL_ENCODING)
		val, err := url.QueryUnescape(e.Value)
		if err != nil {
			log.Printf("[Protocol] Warning: Failed to unescape value for key %s: %v", e.Key, err)
			val = e.Value
		}
		params[e.Key] = val

		// Update Protocol Params map
		p.Params.Set(e.Key, val)
	}

	// Critical: Update STServlet if present
	if st := params["stservlet"]; st != "" {
		p.STServlet = st
		log.Printf("[Protocol] Updated STServlet from XML: %s", st)
	}

	// Storage id for upload comes from XML session id when present.
	if id := params["id"]; id != "" {
		p.FileID = id
		log.Printf("[Protocol] Updated Session ID from XML (upload id): %s", id)
	}

	// Critical: Update Key if present
	if k := params["key"]; k != "" {
		p.Key = k
	}

	// Extract Data ('dat')
	datB64, ok := params["dat"]
	if !ok {
		return nil, "", fmt.Errorf("no 'dat' parameter found in XML manifest")
	}

	// Clean Base64 (Standard Java behavior handling)
	datB64 = strings.TrimSpace(datB64)

	// Decode Base64
	// Try standard first, then URL-safe
	data, err := base64.StdEncoding.DecodeString(datB64)
	if err != nil {
		// Try URL encoding
		data, err = base64.URLEncoding.DecodeString(datB64)
		if err != nil {
			return nil, "", fmt.Errorf("failed to decode 'dat' (Base64): %v", err)
		}
	}

	format := params["format"]
	if format == "" {
		format = "CAdES" // Default
	}

	return data, format, nil
}

// encryptDES encrypts data using DES (ECB mode). Input should be already padded.
func encryptDES(plaintext []byte, key []byte) ([]byte, error) {
	// DES key must be 8 bytes
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

	// Assuming plaintext is already padded to BlockSize
	if len(plaintext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("plaintext is not a multiple of the block size")
	}

	ciphertext := make([]byte, len(plaintext))
	// ECB Mode
	bs := block.BlockSize()
	for i := 0; i < len(plaintext); i += bs {
		block.Encrypt(ciphertext[i:i+bs], plaintext[i:i+bs])
	}

	return ciphertext, nil
}
