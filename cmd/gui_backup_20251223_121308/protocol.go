package main

import (
	"crypto/des"
	"encoding/base64"
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

type ProtocolState struct {
	IsActive   bool
	RTServlet  string
	FileID     string
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
	state.Key = q.Get("key")
	state.RTServlet = q.Get("rtservlet")

	if state.RTServlet == "" || state.FileID == "" {
		return nil, fmt.Errorf("missing required parameters (rtservlet, fileid)")
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

		// Prepare params: start with all captured params
		data := url.Values{}
		for k, v := range p.Params {
			for _, val := range v {
				data.Add(k, val)
			}
		}

		// Enforce/Overwrite critical ops
		data.Set("op", "get")
		data.Set("id", p.FileID)

		// Set version parameter in AutoFirma format
		data.Set("v", "1_0")

		if p.Key != "" {
			data.Set("key", p.Key)
		}

		var req *http.Request
		if method == "GET" {
			reqURL.RawQuery = data.Encode()
			req, err = http.NewRequest("GET", reqURL.String(), nil)
			log.Printf("[Protocol] GET URL: %s", reqURL.String()) // Log full URL
		} else {
			// POST
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

	// Check if valid (size > 100 and starts with %PDF usually, or just size)
	// Some XML files are valid too.
	// If size < 200, typically error message.
	if err == nil && len(body) > 200 {
		// Success with GET
		return saveTemp(body, p.FileID, p.Key)
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

	reqURL, err := url.Parse(p.RTServlet)
	if err != nil {
		return err
	}

	// Use POST for large data
	form := url.Values{}
	// Copy all original params first
	for k, v := range p.Params {
		for _, val := range v {
			form.Add(k, val)
		}
	}

	// Overwrite/Set specific params
	form.Set("op", "put") // Or 'sign'
	form.Set("id", p.FileID)
	form.Set("dat", signatureB64)

	// Set version parameter in AutoFirma format
	form.Set("v", "1_0")

	// Key should already be in Params, but ensure it if logic depends on p.Key
	if p.Key != "" {
		form.Set("key", p.Key)
	}

	// Sometimes 'cert' is needed if server validates it
	if certB64 != "" {
		form.Set("cert", certB64)
	}

	req, err := http.NewRequest("POST", reqURL.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "AutoFirma/1.6.5")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("upload failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		// Read body for error
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server upload error: %d %s - %s", resp.StatusCode, resp.Status, string(body))
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
			// Parse XML to extract actual data
			actualData, format, err := parseAutoFirmaXML(content)
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

// parseAutoFirmaXML extracts the actual data to sign from AutoFirma XML request
func parseAutoFirmaXML(xmlData []byte) ([]byte, string, error) {
	xmlStr := string(xmlData)

	// Extract 'dat' parameter (Base64 encoded data) - more robust approach
	// The dat value can span multiple lines and be very long
	datStart := strings.Index(xmlStr, `<e k="dat" v="`)
	if datStart == -1 {
		return nil, "", fmt.Errorf("no 'dat' parameter found in XML")
	}
	datStart += len(`<e k="dat" v="`)

	// Find the closing quote, handling potential newlines
	datEnd := -1
	for i := datStart; i < len(xmlStr); i++ {
		if xmlStr[i] == '"' {
			datEnd = i
			break
		}
	}
	if datEnd == -1 {
		return nil, "", fmt.Errorf("malformed 'dat' parameter - no closing quote")
	}

	datB64 := xmlStr[datStart:datEnd]

	// Remove all whitespace (newlines, spaces, tabs) from Base64 string
	datB64 = strings.ReplaceAll(datB64, "\n", "")
	datB64 = strings.ReplaceAll(datB64, "\r", "")
	datB64 = strings.ReplaceAll(datB64, " ", "")
	datB64 = strings.ReplaceAll(datB64, "\t", "")

	// Convert URL-safe Base64 to standard Base64
	datB64 = strings.ReplaceAll(datB64, "-", "+")
	datB64 = strings.ReplaceAll(datB64, "_", "/")

	// Decode Base64
	data, err := base64.StdEncoding.DecodeString(datB64)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode 'dat': %v (length=%d)", err, len(datB64))
	}

	// Extract format
	format := "CAdES" // Default
	formatStart := strings.Index(xmlStr, `<e k="format" v="`)
	if formatStart != -1 {
		formatStart += len(`<e k="format" v="`)
		formatEnd := strings.Index(xmlStr[formatStart:], `"`)
		if formatEnd != -1 {
			format = xmlStr[formatStart : formatStart+formatEnd]
		}
	}

	return data, format, nil
}
