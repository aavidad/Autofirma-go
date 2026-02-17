// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package signer

import (
	"autofirma-host/pkg/applog"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"autofirma-host/pkg/certstore"
	"autofirma-host/pkg/protocol"
)

const (
	largePayloadThresholdBytes = 2 * 1024 * 1024

	defaultSignTimeoutSmallSec   = 45
	defaultSignTimeoutLargeSec   = 180
	defaultVerifyTimeoutSmallSec = 30
	defaultVerifyTimeoutLargeSec = 120
	defaultExportTimeoutSec      = 45

	defaultRetriesSmall = 0
	defaultRetriesLarge = 1
)

var (
	getSystemCertificatesFunc            = certstore.GetSystemCertificates
	getSystemCertificatesWithOptionsFunc = certstore.GetSystemCertificatesWithOptions
)

func getEnvInt(name string, def int) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return def
	}
	return n
}

func fileSize(path string) int64 {
	if path == "" {
		return 0
	}
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func timeoutForBytes(size int64, smallEnv, largeEnv string, defSmall, defLarge int) time.Duration {
	if size > largePayloadThresholdBytes {
		return time.Duration(getEnvInt(largeEnv, defLarge)) * time.Second
	}
	return time.Duration(getEnvInt(smallEnv, defSmall)) * time.Second
}

func retriesForBytes(size int64) int {
	if size > largePayloadThresholdBytes {
		return getEnvInt("AUTOFIRMA_RETRIES_LARGE", defaultRetriesLarge)
	}
	return getEnvInt("AUTOFIRMA_RETRIES_SMALL", defaultRetriesSmall)
}

func runCommandWithRetry(args []string, timeout time.Duration, retries int, label string) ([]byte, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("%s: comando vacío", label)
	}

	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		log.Printf("[Exec] %s intento %d/%d comando=%s timeout=%s", label, attempt+1, retries+1, args[0], timeout)
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		configureCommandForOS(cmd)
		output, err := cmd.CombinedOutput()
		cancel()

		if err == nil {
			if len(strings.TrimSpace(string(output))) > 0 {
				log.Printf("[Exec] %s salida (ok): %s", label, truncateForLog(string(output), 800))
			}
			return output, nil
		}

		if ctx.Err() == context.DeadlineExceeded {
			lastErr = fmt.Errorf("%s timeout tras %s (intento %d/%d): %s",
				label, timeout, attempt+1, retries+1, string(output))
		} else {
			lastErr = fmt.Errorf("%s fallo (intento %d/%d): %v, salida: %s",
				label, attempt+1, retries+1, err, string(output))
		}
		log.Printf("[Exec] %s error intento %d/%d: %v", label, attempt+1, retries+1, lastErr)

		if attempt < retries {
			time.Sleep(time.Duration(attempt+1) * time.Second)
		}
	}
	return nil, lastErr
}

func truncateForLog(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "...(truncado)"
}

// SignData signs data using the specified certificate.
func SignData(dataB64 string, certificateID string, pin string, format string, options map[string]interface{}) (string, error) {
	format = normalizeSignFormat(format)
	log.Printf("[Signer] Sign start cert=%s format=%s pin_set=%t opts=%s %s",
		applog.MaskID(certificateID),
		format,
		strings.TrimSpace(pin) != "",
		applog.OptionKeys(options),
		applog.SecretMeta("dataB64", dataB64),
	)

	// Decode base64 data
	data, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		log.Printf("[Signer] Sign decode error cert=%s format=%s err=%v", applog.MaskID(certificateID), format, err)
		return "", fmt.Errorf("datos base64 inválidos: %v", err)
	}
	resolvedFormat := resolveSignFormat(format, data)
	if resolvedFormat != format {
		log.Printf("[Signer] Sign format resolved input=%s resolved=%s", format, resolvedFormat)
	}
	format = resolvedFormat

	// Get certificate by ID
	cert, nickname, err := getCertificateByID(certificateID, options)
	if err != nil {
		log.Printf("[Signer] Sign cert lookup failed cert=%s format=%s err=%v", applog.MaskID(certificateID), format, err)
		return "", fmt.Errorf("certificado no encontrado: %v", err)
	}

	// Enrich PAdES visual/options defaults with signer identity when absent.
	if strings.EqualFold(format, "pades") {
		options = enrichPadesOptions(options, cert)
	}

	// Generate random password for temporary P12
	tempPassword := fmt.Sprintf("auto-%d-%d", time.Now().UnixNano(), os.Getpid())
	var windowsStoreErr error
	var windowsPadesStoreErr error
	// Windows-first strategy for CAdES:
	// 1) sign directly from certificate store (no private key export)
	// 2) fallback to PFX export path only if native signing fails
	if runtime.GOOS == "windows" && strings.EqualFold(format, "cades") {
		sigDER, storeErr := signCadesWithWindowsStore(data, nickname, options)
		if storeErr == nil {
			log.Printf("[Signer] Windows store CAdES signing succeeded (store-first mode)")
			sig := base64.StdEncoding.EncodeToString(sigDER)
			log.Printf("[Signer] Sign success cert=%s format=%s %s", applog.MaskID(certificateID), format, applog.SecretMeta("signatureB64", sig))
			return sig, nil
		}
		windowsStoreErr = storeErr
		log.Printf("[Signer] Windows store CAdES signing failed, falling back to PFX path: %v", storeErr)
	}

	// Windows-first strategy for PAdES:
	// 1) sign PDF using Windows certificate store without exporting private key
	// 2) fallback to PFX export path only if store-native PAdES fails
	if runtime.GOOS == "windows" && strings.EqualFold(format, "pades") {
		inputFile := filepath.Join(os.TempDir(), fmt.Sprintf("autofirma-input-%d", time.Now().UnixNano()))
		defer os.Remove(inputFile)
		if err := os.WriteFile(inputFile, data, 0600); err != nil {
			return "", fmt.Errorf("fallo al escribir archivo de entrada: %v", err)
		}
		signedData, storeErr := signPadesWithWindowsStoreGo(inputFile, cert, nickname, options)
		if storeErr == nil {
			log.Printf("[Signer] Windows store PAdES signing succeeded (store-first mode)")
			sig := base64.StdEncoding.EncodeToString(signedData)
			log.Printf("[Signer] Sign success cert=%s format=%s %s", applog.MaskID(certificateID), format, applog.SecretMeta("signatureB64", sig))
			return sig, nil
		}
		windowsPadesStoreErr = storeErr
		log.Printf("[Signer] Windows store PAdES signing failed, falling back to PFX path: %v", storeErr)
	}

	// Export certificate and private key to temporary PKCS#12
	p12Path, err := exportCertificateToP12(nickname, tempPassword)
	if err != nil {
		if windowsStoreErr != nil && runtime.GOOS == "windows" && strings.EqualFold(format, "cades") {
			if isNonExportableKeyError(err) {
				return "", fmt.Errorf("fallo al firmar en el almacen de Windows: %v", windowsStoreErr)
			}
			return "", fmt.Errorf("fallo al firmar en el almacen de Windows: %v (fallback por exportacion tambien fallo: %v)", windowsStoreErr, err)
		}
		if windowsPadesStoreErr != nil && runtime.GOOS == "windows" && strings.EqualFold(format, "pades") {
			if isNonExportableKeyError(err) {
				return "", fmt.Errorf("fallo al firmar PAdES en el almacen de Windows: %v", windowsPadesStoreErr)
			}
			return "", fmt.Errorf("fallo al firmar PAdES en el almacen de Windows: %v (fallback por exportacion tambien fallo: %v)", windowsPadesStoreErr, err)
		}
		if runtime.GOOS == "windows" && isNonExportableKeyError(err) {
			return "", fmt.Errorf("el certificado seleccionado no permite exportar su clave privada")
		}
		return "", fmt.Errorf("fallo al exportar certificado: %v", err)
	}
	defer os.Remove(p12Path)

	// Create temporary files for input/output
	inputFile := filepath.Join(os.TempDir(), fmt.Sprintf("autofirma-input-%d", time.Now().UnixNano()))
	outputFile := filepath.Join(os.TempDir(), fmt.Sprintf("autofirma-output-%d", time.Now().UnixNano()))
	defer os.Remove(inputFile)
	defer os.Remove(outputFile)

	// Write input data
	if err := os.WriteFile(inputFile, data, 0600); err != nil {
		return "", fmt.Errorf("fallo al escribir archivo de entrada: %v", err)
	}

	// CAdES detached path without Node.js (OpenSSL backend).
	if strings.EqualFold(format, "cades") {
		signedData, err := signCadesDetachedOpenSSL(inputFile, p12Path, tempPassword, options)
		if err != nil {
			log.Printf("[Signer] Sign failure cert=%s format=%s err=%v", applog.MaskID(certificateID), format, err)
			return "", fmt.Errorf("firma CAdES fallida (openssl): %v", err)
		}
		sig := base64.StdEncoding.EncodeToString(signedData)
		log.Printf("[Signer] Sign success cert=%s format=%s %s", applog.MaskID(certificateID), format, applog.SecretMeta("signatureB64", sig))
		return sig, nil
	}

	// PAdES path without Node.js.
	if strings.EqualFold(format, "pades") {
		signedData, err := signPadesWithGo(inputFile, p12Path, tempPassword, options)
		if err != nil {
			log.Printf("[Signer] Sign failure cert=%s format=%s err=%v", applog.MaskID(certificateID), format, err)
			return "", fmt.Errorf("firma PAdES fallida (go): %v", err)
		}
		sig := base64.StdEncoding.EncodeToString(signedData)
		log.Printf("[Signer] Sign success cert=%s format=%s %s", applog.MaskID(certificateID), format, applog.SecretMeta("signatureB64", sig))
		return sig, nil
	}

	// XAdES path without Node.js.
	if strings.EqualFold(format, "xades") {
		signedData, err := signXadesWithGo(inputFile, p12Path, tempPassword, options)
		if err != nil {
			log.Printf("[Signer] Sign failure cert=%s format=%s err=%v", applog.MaskID(certificateID), format, err)
			return "", fmt.Errorf("firma XAdES fallida (go): %v", err)
		}
		sig := base64.StdEncoding.EncodeToString(signedData)
		log.Printf("[Signer] Sign success cert=%s format=%s %s", applog.MaskID(certificateID), format, applog.SecretMeta("signatureB64", sig))
		return sig, nil
	}

	log.Printf("[Signer] Sign unsupported format cert=%s format=%s", applog.MaskID(certificateID), format)
	return "", fmt.Errorf("formato de firma no soportado: %s", format)
}

func isNonExportableKeyError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	indicators := []string{
		"no exportable",
		"non-exportable",
		"export-pfxcertificate",
		"cannot export",
		"private key is not exportable",
		"key not valid for use in specified state",
		"0x8009000b",
		"0x80090010",
	}
	for _, s := range indicators {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

func psSingleQuote(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// signCadesWithWindowsStore signs detached CMS using CurrentUser\\My without exporting private key.
func signCadesWithWindowsStore(data []byte, thumbprint string, options map[string]interface{}) ([]byte, error) {
	inFile := filepath.Join(os.TempDir(), fmt.Sprintf("autofirma-win-in-%d.bin", time.Now().UnixNano()))
	outFile := filepath.Join(os.TempDir(), fmt.Sprintf("autofirma-win-out-%d.p7s", time.Now().UnixNano()))
	defer os.Remove(inFile)
	defer os.Remove(outFile)

	if err := os.WriteFile(inFile, data, 0600); err != nil {
		return nil, fmt.Errorf("no se pudo escribir input temporal: %v", err)
	}

	thumb := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(thumbprint), " ", ""))
	if thumb == "" {
		return nil, fmt.Errorf("thumbprint vacio")
	}

	// Use .NET SignedCms (detached) with store key.
	digestOID := resolveDigestOID(options, "2.16.840.1.101.3.4.2.1")
	ps := "$ErrorActionPreference='Stop'; " +
		"try { Add-Type -AssemblyName 'System.Security.Cryptography.Pkcs' -ErrorAction Stop } catch {}; " +
		"try { Add-Type -AssemblyName 'System.Security' -ErrorAction Stop } catch {}; " +
		"$thumb='" + psSingleQuote(thumb) + "'; " +
		"$in='" + psSingleQuote(inFile) + "'; " +
		"$out='" + psSingleQuote(outFile) + "'; " +
		"$digestOid='" + psSingleQuote(digestOID) + "'; " +
		"$cert=Get-Item ('Cert:\\CurrentUser\\My\\' + $thumb); " +
		"$bytes=[System.IO.File]::ReadAllBytes($in); " +
		"$ci=New-Object System.Security.Cryptography.Pkcs.ContentInfo (, $bytes); " +
		"$cms=New-Object System.Security.Cryptography.Pkcs.SignedCms ($ci, $true); " +
		"$signer=New-Object System.Security.Cryptography.Pkcs.CmsSigner ($cert); " +
		"if ($null -ne ($signer | Get-Member -Name DirectSignature -MemberType Property -ErrorAction SilentlyContinue)) { $signer.DirectSignature=$false }; " +
		"$signer.IncludeOption=[System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly; " +
		"$signer.DigestAlgorithm=New-Object System.Security.Cryptography.Oid($digestOid); " +
		"$signer.SignedAttributes.Add((New-Object System.Security.Cryptography.Pkcs.Pkcs9SigningTime)); " +
		"$cms.ComputeSignature($signer, $false); " +
		"[System.IO.File]::WriteAllBytes($out, $cms.Encode())"

	timeout := time.Duration(getEnvInt("AUTOFIRMA_SIGN_TIMEOUT_SMALL_SEC", defaultSignTimeoutSmallSec)) * time.Second
	retries := getEnvInt("AUTOFIRMA_RETRIES_SMALL", defaultRetriesSmall)
	_, err := runCommandWithRetry(
		[]string{"powershell", "-NoProfile", "-NonInteractive", "-Command", ps},
		timeout,
		retries,
		"respaldo SignedCms",
	)
	if err != nil {
		return nil, err
	}

	out, err := os.ReadFile(outFile)
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer firma CMS generada: %v", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("firma CMS vacia")
	}
	return out, nil
}

// VerificationResult holds the result of a signature verification
// (Deleted, using protocol.VerifyResult)

// VerifyData verifies a signature.
func VerifyData(originalDataB64, signatureDataB64, format string) (*protocol.VerifyResult, error) {
	format = normalizeSignFormat(format)
	log.Printf("[Signer] Verify start format=%s %s %s",
		format,
		applog.SecretMeta("originalDataB64", originalDataB64),
		applog.SecretMeta("signatureDataB64", signatureDataB64),
	)

	// Decode base64 original data
	originalData, err := base64.StdEncoding.DecodeString(originalDataB64)
	if err != nil {
		log.Printf("[Signer] Verify decode original error format=%s err=%v", format, err)
		return nil, fmt.Errorf("datos originales base64 inválidos: %v", err)
	}

	// Helper to create temp file
	createTemp := func(data []byte) (string, error) {
		f, err := os.CreateTemp("", "autofirma-verify-*")
		if err != nil {
			return "", err
		}
		defer f.Close()
		if _, err := f.Write(data); err != nil {
			os.Remove(f.Name())
			return "", err
		}
		return f.Name(), nil
	}

	// Create temporary file for original input
	originalFile, err := createTemp(originalData)
	if err != nil {
		return nil, fmt.Errorf("fallo al escribir archivo temporal de datos originales: %v", err)
	}
	defer os.Remove(originalFile)

	var signatureFile string
	if signatureDataB64 != "" {
		// Decode base64 signature data
		signatureData, err := base64.StdEncoding.DecodeString(signatureDataB64)
		if err != nil {
			log.Printf("[Signer] Verify decode signature error format=%s err=%v", format, err)
			return nil, fmt.Errorf("datos de firma base64 inválidos: %v", err)
		}

		// Create temporary file for signature input
		signatureFile, err = createTemp(signatureData)
		if err != nil {
			return nil, fmt.Errorf("fallo al escribir archivo temporal de firma: %v", err)
		}
		defer os.Remove(signatureFile)
	}

	// CAdES detached verification without Node.js (OpenSSL backend).
	if strings.EqualFold(format, "cades") {
		if signatureFile == "" {
			return nil, fmt.Errorf("verificación CAdES requiere signatureData")
		}
		result, err := verifyCadesDetachedOpenSSL(originalFile, signatureFile)
		if err != nil {
			log.Printf("[Signer] Verify failure format=%s err=%v", format, err)
			return nil, fmt.Errorf("verificación CAdES fallida (openssl): %v", err)
		}
		log.Printf("[Signer] Verify success format=%s valid=%t signer=%q", format, result.Valid, result.SignerName)
		return result, nil
	}

	// PAdES verification path without Node.js.
	if strings.EqualFold(format, "pades") {
		target := originalFile
		if signatureFile != "" {
			target = signatureFile
		}
		result, err := verifyPadesWithGo(target)
		if err != nil {
			log.Printf("[Signer] Verify failure format=%s err=%v", format, err)
			return nil, fmt.Errorf("verificación PAdES fallida (go): %v", err)
		}
		log.Printf("[Signer] Verify success format=%s valid=%t signer=%q", format, result.Valid, result.SignerName)
		return result, nil
	}

	// XAdES verification path without Node.js.
	if strings.EqualFold(format, "xades") {
		target := originalFile
		if signatureFile != "" {
			target = signatureFile
		}
		result, err := verifyXadesWithGo(target)
		if err != nil {
			log.Printf("[Signer] Verify failure format=%s err=%v", format, err)
			return nil, fmt.Errorf("verificación XAdES fallida (go): %v", err)
		}
		log.Printf("[Signer] Verify success format=%s valid=%t signer=%q", format, result.Valid, result.SignerName)
		return result, nil
	}

	log.Printf("[Signer] Verify unsupported format=%s", format)
	return nil, fmt.Errorf("formato de verificacion no soportado: %s", format)
}

// getCertificateByID finds certificate by fingerprint ID
func getCertificateByID(certificateID string, options map[string]interface{}) (*protocol.Certificate, string, error) {
	certs, err := getCertificatesForSignOptions(options)
	if err != nil {
		return nil, "", err
	}

	// Find certificate with matching ID
	for i := range certs {
		cert := certs[i]
		if cert.ID != certificateID {
			continue
		}
		if cert.Nickname != "" {
			return &cert, cert.Nickname, nil
		}
		// Best-effort: when selected cert came from a source without nickname
		// (e.g. raw PKCS#11 scan), retry against default lookup to find an
		// equivalent certificate with export nickname.
		if fallback, ok := findCertificateWithNickname(certs[i]); ok {
			return &fallback, fallback.Nickname, nil
		}
		return nil, "", fmt.Errorf("el certificado no tiene apodo (nickname)")
	}

	return nil, "", fmt.Errorf("certificado no encontrado")
}

func getCertificatesForSignOptions(options map[string]interface{}) ([]protocol.Certificate, error) {
	storePref, hints, includePKCS11, hasHintsOrOverride := resolveCertstoreOptions(options)
	if hasHintsOrOverride {
		log.Printf("[Signer] loading certificates with store options store=%s include_pkcs11=%t hints=%d",
			storePref, includePKCS11, len(hints))
		certs, err := getSystemCertificatesWithOptionsFunc(certstore.Options{
			PKCS11ModulePaths: hints,
			IncludePKCS11:     includePKCS11,
		})
		if err == nil {
			if len(hints) > 0 && storePref == "PKCS11" && !hasPKCS11Certificates(certs) {
				log.Printf("[Signer] PKCS11 hints yielded no token certificates, retrying default PKCS11 discovery")
				return getSystemCertificatesFunc()
			}
			return certs, nil
		}
		log.Printf("[Signer] options certificate loader failed, fallback to default: %v", err)
	}
	return getSystemCertificatesFunc()
}

func resolveCertstoreOptions(options map[string]interface{}) (store string, hints []string, includePKCS11 bool, hasHintsOrOverride bool) {
	store = strings.ToUpper(strings.TrimSpace(optionString(options, "_defaultKeyStore", "")))
	includePKCS11 = shouldIncludePKCS11ForStore(store)
	hasOverride := store != ""
	if optionBool(options, "_disableOpeningExternalStores", false) && store != "PKCS11" {
		includePKCS11 = false
		hasOverride = true
	}
	rawLib := optionString(options, "_defaultKeyStoreLib", "")
	if strings.EqualFold(store, "PKCS11") && strings.TrimSpace(rawLib) != "" {
		hints = splitStoreLibHints(rawLib)
	}
	return store, hints, includePKCS11, hasOverride || len(hints) > 0 || !includePKCS11
}

func shouldIncludePKCS11ForStore(store string) bool {
	switch strings.ToUpper(strings.TrimSpace(store)) {
	case "":
		return true
	case "PKCS11":
		return true
	case "MOZ_UNI", "SHARED_NSS", "MOZILLA", "WINDOWS", "WINADDRESSBOOK", "APPLE", "MACOS", "KEYCHAIN":
		return false
	default:
		return true
	}
}

func splitStoreLibHints(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool { return r == ';' || r == ',' })
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func findCertificateWithNickname(selected protocol.Certificate) (protocol.Certificate, bool) {
	certs, err := getSystemCertificatesFunc()
	if err != nil {
		return protocol.Certificate{}, false
	}
	for i := range certs {
		cert := certs[i]
		if cert.Nickname == "" {
			continue
		}
		if cert.ID == selected.ID || sameCertificate(cert, selected) {
			return cert, true
		}
	}
	return protocol.Certificate{}, false
}

func sameCertificate(a, b protocol.Certificate) bool {
	if strings.EqualFold(strings.TrimSpace(a.Fingerprint), strings.TrimSpace(b.Fingerprint)) &&
		strings.TrimSpace(a.Fingerprint) != "" && strings.TrimSpace(b.Fingerprint) != "" {
		return true
	}
	if len(a.Content) > 0 && len(b.Content) > 0 && bytes.Equal(a.Content, b.Content) {
		return true
	}
	return false
}

func hasPKCS11Certificates(certs []protocol.Certificate) bool {
	for _, c := range certs {
		src := strings.ToLower(strings.TrimSpace(c.Source))
		if src == "smartcard" || src == "dnie" {
			return true
		}
	}
	return false
}

// exportCertificateToP12 exports certificate and private key to PKCS#12.
// On Linux this uses NSS (pk12util + nickname).
// On Windows this uses CurrentUser\\My thumbprint + Export-PfxCertificate.
func exportCertificateToP12(nickname, password string) (string, error) {
	timeout := time.Duration(getEnvInt("AUTOFIRMA_EXPORT_TIMEOUT_SEC", defaultExportTimeoutSec)) * time.Second
	retries := getEnvInt("AUTOFIRMA_EXPORT_RETRIES", defaultRetriesSmall)

	if runtime.GOOS == "windows" {
		tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("autofirma-cert-%d.pfx", time.Now().UnixNano()))
		thumb := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(nickname), " ", ""))
		if thumb == "" {
			return "", fmt.Errorf("thumbprint de certificado vacio")
		}
		log.Printf("[Signer] Intentando exportar certificado a PFX. thumb=%s destino=%s", maskThumbprint(thumb), tmpFile)
		logWindowsCertificateDiagnostics(thumb)

		ps := "$ErrorActionPreference='Stop'; " +
			"$pwd = ConvertTo-SecureString -String '" + password + "' -AsPlainText -Force; " +
			"$cert = Get-Item 'Cert:\\CurrentUser\\My\\" + thumb + "'; " +
			"Export-PfxCertificate -Cert $cert -FilePath '" + tmpFile + "' -Password $pwd -Force | Out-Null"

		_, err := runCommandWithRetry(
			[]string{"powershell", "-NoProfile", "-NonInteractive", "-Command", ps},
			timeout,
			retries,
			"Export-PfxCertificate",
		)
		if err != nil {
			return "", fmt.Errorf("Export-PfxCertificate fallo (clave no exportable o acceso denegado): %v", err)
		}
		return tmpFile, nil
	}

	nssDB := filepath.Join(os.Getenv("HOME"), ".pki/nssdb")
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("autofirma-cert-%d.p12", time.Now().UnixNano()))

	_, err := runCommandWithRetry(
		[]string{"pk12util", "-o", tmpFile, "-d", "sql:" + nssDB, "-n", nickname, "-W", password},
		timeout,
		retries,
		"pk12util",
	)
	if err != nil {
		return "", fmt.Errorf("pk12util falló: %v", err)
	}
	return tmpFile, nil
}

func maskThumbprint(thumb string) string {
	thumb = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(thumb), " ", ""))
	if len(thumb) <= 12 {
		return thumb
	}
	return thumb[:8] + "..." + thumb[len(thumb)-4:]
}

func logWindowsCertificateDiagnostics(thumb string) {
	if runtime.GOOS != "windows" {
		return
	}

	ps := "$ErrorActionPreference='Stop'; " +
		"$thumb='" + psSingleQuote(thumb) + "'; " +
		"$cert=Get-Item ('Cert:\\CurrentUser\\My\\' + $thumb); " +
		"$res=[ordered]@{Thumbprint=$cert.Thumbprint;Subject=$cert.Subject;Issuer=$cert.Issuer;HasPrivateKey=$cert.HasPrivateKey;NotAfter=$cert.NotAfter.ToString('o');SignatureAlgorithm=$cert.SignatureAlgorithm.FriendlyName;PublicKeyOid=$cert.PublicKey.Oid.Value}; " +
		"try { $pk=$cert.PrivateKey; if ($null -ne $pk) { $res.PrivateKeyType=$pk.GetType().FullName; if ($null -ne $pk.CspKeyContainerInfo) { $res.LegacyExportable=$pk.CspKeyContainerInfo.Exportable; $res.HardwareDevice=$pk.CspKeyContainerInfo.HardwareDevice; $res.ProviderName=$pk.CspKeyContainerInfo.ProviderName } } } catch { $res.PrivateKeyInfoError=$_.Exception.Message }; " +
		"try { $rsa=[System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert); if ($null -ne $rsa) { $res.RsaPrivateKeyType=$rsa.GetType().FullName; if ($rsa -is [System.Security.Cryptography.RSACng]) { $res.CngProvider=$rsa.Key.Provider.Provider; $res.CngExportPolicy=$rsa.Key.ExportPolicy.ToString() } } } catch { $res.RsaPrivateKeyError=$_.Exception.Message }; " +
		"$res | ConvertTo-Json -Compress"

	output, err := runCommandWithRetry(
		[]string{"powershell", "-NoProfile", "-NonInteractive", "-Command", ps},
		15*time.Second,
		0,
		"WinCertDiagnostics",
	)
	if err != nil {
		log.Printf("[Signer] Win cert diagnostics failed thumb=%s: %v", maskThumbprint(thumb), err)
		return
	}
	log.Printf("[Signer] Win cert diagnostics thumb=%s data=%s", maskThumbprint(thumb), truncateForLog(string(output), 2000))
}

func enrichPadesOptions(opts map[string]interface{}, cert *protocol.Certificate) map[string]interface{} {
	if opts == nil {
		opts = map[string]interface{}{}
	}
	if cert == nil {
		return opts
	}
	if _, ok := opts["signerName"]; !ok {
		if cn := strings.TrimSpace(cert.Subject["CN"]); cn != "" {
			opts["signerName"] = cn
		}
	}
	if _, ok := opts["issuerName"]; !ok {
		if icn := strings.TrimSpace(cert.Issuer["CN"]); icn != "" {
			opts["issuerName"] = icn
		}
	}
	if _, ok := opts["issuerOrg"]; !ok {
		if io := strings.TrimSpace(cert.Issuer["O"]); io != "" {
			opts["issuerOrg"] = io
		}
	}
	if _, ok := opts["signerDNI"]; !ok {
		// Best-effort: use subject serialNumber if available, fallback to cert serial.
		if sn := strings.TrimSpace(cert.Subject["SERIALNUMBER"]); sn != "" {
			opts["signerDNI"] = sn
		} else if serial := strings.TrimSpace(cert.SerialNumber); serial != "" {
			opts["signerDNI"] = serial
		}
	}
	return opts
}

// (Function removed)
