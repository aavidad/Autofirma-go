// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"autofirma-host/pkg/protocol"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

var (
	cliModeFlag              = flag.Bool("cli", false, "Ejecutar en modo línea de comandos sin interfaz gráfica")
	cliHelpFlag              = flag.Bool("cli-help", false, "Mostrar ayuda específica del modo CLI con ejemplos y salir")
	cliOperationFlag         = flag.String("op", "", "Operación CLI: sign|cosign|countersign|verify")
	cliInputFlag             = flag.String("in", "", "Ruta del fichero de entrada (PDF/XML/SIG)")
	cliOutputFlag            = flag.String("out", "", "Ruta del fichero de salida firmado")
	cliFormatFlag            = flag.String("format", "", "Formato de firma/verificación: auto|pades|cades|xades")
	cliCertIDFlag            = flag.String("cert-id", "", "ID exacto del certificado a usar")
	cliCertIndexFlag         = flag.Int("cert-index", -1, "Índice del certificado (según -list-certs)")
	cliCertContainsFlag      = flag.String("cert-contains", "", "Texto parcial para seleccionar certificado por CN/Nickname/serie")
	cliListCertsFlag         = flag.Bool("list-certs", false, "Listar certificados disponibles y salir")
	cliCheckCertsFlag        = flag.Bool("check-certs", false, "Comprobar capacidad de firma de certificados")
	cliJSONFlag              = flag.Bool("json", false, "Mostrar salida en JSON")
	cliNoSaveFlag            = flag.Bool("no-save", false, "No guardar fichero firmado en disco (solo salida por consola/JSON)")
	cliPrintSignatureB64Flag = flag.Bool("print-signature", false, "Imprimir firma Base64 en stdout")
	cliAllowInvalidPDFFlag   = flag.Bool("allow-invalid-pdf", false, "Permitir PDF no válido en PAdES (bajo responsabilidad)")
	cliStrictCompatFlag      = flag.Bool("strict-compat", false, "Aplicar defaults de compatibilidad estricta Java")
	cliOverwriteFlag         = flag.String("overwrite", "rename", "Política al existir salida: fail|rename|force")
	cliVisibleSealFlag       = flag.Bool("visible-seal", false, "Añadir firma visible en PAdES")
	cliSealPageFlag          = flag.Uint("seal-page", 1, "Página de la firma visible (>=1)")
	cliSealXFlag             = flag.Float64("seal-x", 0.62, "X normalizada (0..1) del sello visible")
	cliSealYFlag             = flag.Float64("seal-y", 0.04, "Y normalizada (0..1) del sello visible")
	cliSealWFlag             = flag.Float64("seal-w", 0.34, "Ancho normalizado (0..1) del sello visible")
	cliSealHFlag             = flag.Float64("seal-h", 0.12, "Alto normalizado (0..1) del sello visible")
	cliSealLayoutFlag        = flag.String("seal-layout", "manual", "Layout del sello visible: manual|footer")
	cliSealFooterMarginFlag  = flag.Float64("seal-footer-margin", 0.02, "Margen normalizado (0..1) para layout footer")
	cliDomainFlag            = flag.String("domain", "", "Dominio para operaciones de confianza (domains-add/domains-remove)")

	// Alias en castellano (compatibles con flags existentes).
	cliModoFlag                = flag.Bool("modo-cli", false, "Alias de -cli")
	cliAyudaFlag               = flag.Bool("ayuda-cli", false, "Alias de -cli-help")
	cliOperacionFlag           = flag.String("operacion", "", "Alias de -op")
	cliEntradaFlag             = flag.String("entrada", "", "Alias de -in")
	cliSalidaFlag              = flag.String("salida", "", "Alias de -out")
	cliFormatoFlag             = flag.String("formato", "", "Alias de -format")
	cliCertIDCastFlag          = flag.String("id-certificado", "", "Alias de -cert-id")
	cliCertIndiceFlag          = flag.Int("indice-certificado", -1, "Alias de -cert-index")
	cliCertContieneFlag        = flag.String("certificado-contiene", "", "Alias de -cert-contains")
	cliListarCertsFlag         = flag.Bool("listar-certificados", false, "Alias de -list-certs")
	cliComprobarCertsFlag      = flag.Bool("comprobar-certificados", false, "Alias de -check-certs")
	cliSalidaJSONFlag          = flag.Bool("salida-json", false, "Alias de -json")
	cliNoGuardarFlag           = flag.Bool("no-guardar", false, "Alias de -no-save")
	cliImprimirFirmaFlag       = flag.Bool("imprimir-firma", false, "Alias de -print-signature")
	cliPermitirPDFInvalidoFlag = flag.Bool("permitir-pdf-invalido", false, "Alias de -allow-invalid-pdf")
	cliCompatibilidadEstricta  = flag.Bool("compatibilidad-estricta", false, "Alias de -strict-compat")
	cliSobrescribirFlag        = flag.String("sobrescribir", "", "Alias de -overwrite")
	cliSelloVisibleFlag        = flag.Bool("sello-visible", false, "Alias de -visible-seal")
	cliSelloPaginaFlag         = flag.Uint("sello-pagina", 0, "Alias de -seal-page")
	cliSelloXFlag              = flag.Float64("sello-x", -1, "Alias de -seal-x")
	cliSelloYFlag              = flag.Float64("sello-y", -1, "Alias de -seal-y")
	cliSelloWFlag              = flag.Float64("sello-ancho", -1, "Alias de -seal-w")
	cliSelloHFlag              = flag.Float64("sello-alto", -1, "Alias de -seal-h")
	cliDisposicionSelloFlag    = flag.String("disposicion-sello", "", "Alias de -seal-layout")
	cliMargenInferiorSelloFlag = flag.Float64("margen-inferior-sello", -1, "Alias de -seal-footer-margin")
	cliDominioFlagCast         = flag.String("dominio", "", "Alias de -domain")
)

func applyCLISpanishAliases() {
	if *cliModoFlag {
		*cliModeFlag = true
	}
	if *cliAyudaFlag {
		*cliHelpFlag = true
	}
	if v := strings.TrimSpace(*cliOperacionFlag); v != "" {
		*cliOperationFlag = v
	}
	if v := strings.TrimSpace(*cliEntradaFlag); v != "" {
		*cliInputFlag = v
	}
	if v := strings.TrimSpace(*cliSalidaFlag); v != "" {
		*cliOutputFlag = v
	}
	if v := strings.TrimSpace(*cliFormatoFlag); v != "" {
		*cliFormatFlag = v
	}
	if v := strings.TrimSpace(*cliCertIDCastFlag); v != "" {
		*cliCertIDFlag = v
	}
	if *cliCertIndiceFlag >= 0 {
		*cliCertIndexFlag = *cliCertIndiceFlag
	}
	if v := strings.TrimSpace(*cliCertContieneFlag); v != "" {
		*cliCertContainsFlag = v
	}
	if *cliListarCertsFlag {
		*cliListCertsFlag = true
	}
	if *cliComprobarCertsFlag {
		*cliCheckCertsFlag = true
	}
	if *cliSalidaJSONFlag {
		*cliJSONFlag = true
	}
	if *cliNoGuardarFlag {
		*cliNoSaveFlag = true
	}
	if *cliImprimirFirmaFlag {
		*cliPrintSignatureB64Flag = true
	}
	if *cliPermitirPDFInvalidoFlag {
		*cliAllowInvalidPDFFlag = true
	}
	if *cliCompatibilidadEstricta {
		*cliStrictCompatFlag = true
	}
	if v := strings.TrimSpace(*cliSobrescribirFlag); v != "" {
		*cliOverwriteFlag = v
	}
	if *cliSelloVisibleFlag {
		*cliVisibleSealFlag = true
	}
	if *cliSelloPaginaFlag > 0 {
		*cliSealPageFlag = *cliSelloPaginaFlag
	}
	if *cliSelloXFlag >= 0 {
		*cliSealXFlag = *cliSelloXFlag
	}
	if *cliSelloYFlag >= 0 {
		*cliSealYFlag = *cliSelloYFlag
	}
	if *cliSelloWFlag >= 0 {
		*cliSealWFlag = *cliSelloWFlag
	}
	if *cliSelloHFlag >= 0 {
		*cliSealHFlag = *cliSelloHFlag
	}
	if v := strings.TrimSpace(*cliDisposicionSelloFlag); v != "" {
		*cliSealLayoutFlag = v
	}
	if *cliMargenInferiorSelloFlag >= 0 {
		*cliSealFooterMarginFlag = *cliMargenInferiorSelloFlag
	}
	if v := strings.TrimSpace(*cliDominioFlagCast); v != "" {
		*cliDomainFlag = v
	}
}

func normalizeCLIOperation(op string) string {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case "firmar":
		return "sign"
	case "cofirmar":
		return "cosign"
	case "contrafirmar":
		return "countersign"
	case "verificar":
		return "verify"
	case "informe-diagnostico":
		return "diagnostics-report"
	case "listar-dominios":
		return "domains-list"
	case "anadir-dominio", "añadir-dominio":
		return "domains-add"
	case "eliminar-dominio":
		return "domains-remove"
	case "estado-almacen-tls":
		return "tls-store-status"
	case "limpiar-almacen-tls":
		return "tls-store-clear"
	case "estado-confianza-tls":
		return "tls-trust-status"
	case "generar-certificados-tls":
		return "tls-generate-certs"
	case "instalar-confianza-tls":
		return "tls-install-trust"
	default:
		return strings.ToLower(strings.TrimSpace(op))
	}
}

func isCLIModeRequested() bool {
	applyCLISpanishAliases()
	if *cliModeFlag || *cliHelpFlag {
		return true
	}
	if strings.TrimSpace(*cliOperationFlag) != "" {
		return true
	}
	return *cliListCertsFlag || *cliCheckCertsFlag
}

func runCLIMode() error {
	applyCLISpanishAliases()
	if *cliHelpFlag {
		writeCLIHelp(os.Stdout, os.Args[0])
		return nil
	}
	if *cliModeFlag && strings.TrimSpace(*cliOperationFlag) == "" && !*cliListCertsFlag && !*cliCheckCertsFlag {
		writeCLIHelp(os.Stdout, os.Args[0])
		return nil
	}

	core := NewCoreService()
	needCerts := *cliListCertsFlag || *cliCheckCertsFlag || strings.EqualFold(strings.TrimSpace(*cliOperationFlag), "sign") || strings.EqualFold(strings.TrimSpace(*cliOperationFlag), "cosign") || strings.EqualFold(strings.TrimSpace(*cliOperationFlag), "countersign")
	var certs []protocol.Certificate
	var err error
	if needCerts {
		certs, err = core.LoadCertificates()
		if err != nil {
			return fmt.Errorf("no se pudieron cargar certificados: %w", err)
		}
	}

	if *cliCheckCertsFlag {
		certs, _, _ = core.CheckCertificates(certs)
	}

	if *cliListCertsFlag || *cliCheckCertsFlag {
		printCertificatesCLI(certs)
		if strings.TrimSpace(*cliOperationFlag) == "" {
			return nil
		}
	}

	op := normalizeCLIOperation(*cliOperationFlag)
	if op == "" {
		return nil
	}

	switch op {
	case "verify":
		return runCLIVerify(core)
	case "diagnostics-report":
		return runCLIDiagnosticsReport(core)
	case "domains-list":
		return runCLIDomainsList()
	case "domains-add":
		return runCLIDomainsAdd()
	case "domains-remove":
		return runCLIDomainsRemove()
	case "tls-store-status":
		return runCLITLSStoreStatus()
	case "tls-store-clear":
		return runCLITLSStoreClear()
	case "tls-trust-status":
		return runCLITLSTrustStatus()
	case "tls-generate-certs":
		return runCLITLSGenerateCerts()
	case "tls-install-trust":
		return runCLITLSInstallTrust()
	case "sign", "cosign", "countersign":
		return runCLISign(core, certs, op)
	default:
		return fmt.Errorf("operación no soportada en CLI: %s", op)
	}
}

func runCLIDiagnosticsReport(core *CoreService) error {
	certs, err := core.LoadCertificates()
	if err != nil {
		return err
	}
	certs, _, _ = core.CheckCertificates(certs)
	canSign := 0
	for _, c := range certs {
		if c.CanSign {
			canSign++
		}
	}
	storeDir, storeCount := endpointTrustStoreStatus()
	trustLines, trustErr := localTLSTrustStatus()
	out := map[string]interface{}{
		"ok":                 true,
		"certificateCount":   len(certs),
		"canSignCount":       canSign,
		"trustedDomains":     trustedSigningDomainsSnapshot(),
		"endpointStoreDir":   storeDir,
		"endpointStoreCount": storeCount,
		"trustStatusLines":   trustLines,
	}
	if trustErr != nil {
		out["trustStatusError"] = trustErr.Error()
	}
	if *cliJSONFlag {
		return writeJSONOut(out)
	}
	fmt.Printf("Certificados: %d (aptos para firma: %d)\n", len(certs), canSign)
	fmt.Printf("Dominios confiados: %v\n", trustedSigningDomainsSnapshot())
	fmt.Printf("TLS endpoint store: %s (certificados=%d)\n", storeDir, storeCount)
	for _, line := range trustLines {
		fmt.Println(line)
	}
	if trustErr != nil {
		fmt.Printf("Error trust-status: %v\n", trustErr)
	}
	return nil
}

func runCLIDomainsList() error {
	domains := trustedSigningDomainsSnapshot()
	if *cliJSONFlag {
		return writeJSONOut(map[string]interface{}{"ok": true, "domains": domains})
	}
	if len(domains) == 0 {
		fmt.Println("No hay dominios confiados.")
		return nil
	}
	for _, d := range domains {
		fmt.Println(d)
	}
	return nil
}

func runCLIDomainsAdd() error {
	d := strings.TrimSpace(*cliDomainFlag)
	if d == "" {
		return fmt.Errorf("debe indicar -domain o -dominio para domains-add")
	}
	if err := addTrustedSigningDomain(d); err != nil {
		return err
	}
	return runCLIDomainsList()
}

func runCLIDomainsRemove() error {
	d := strings.TrimSpace(*cliDomainFlag)
	if d == "" {
		return fmt.Errorf("debe indicar -domain o -dominio para domains-remove")
	}
	if err := removeTrustedSigningDomain(d); err != nil {
		return err
	}
	return runCLIDomainsList()
}

func runCLITLSStoreStatus() error {
	dir, count := endpointTrustStoreStatus()
	if *cliJSONFlag {
		return writeJSONOut(map[string]interface{}{"ok": true, "endpointStoreDir": dir, "endpointStoreCount": count})
	}
	fmt.Printf("TLS endpoint store: %s (certificados=%d)\n", dir, count)
	return nil
}

func runCLITLSStoreClear() error {
	removed, err := clearEndpointTrustStore()
	if err != nil {
		return err
	}
	dir, count := endpointTrustStoreStatus()
	if *cliJSONFlag {
		return writeJSONOut(map[string]interface{}{
			"ok":                 true,
			"removed":            removed,
			"endpointStoreDir":   dir,
			"endpointStoreCount": count,
		})
	}
	fmt.Printf("TLS endpoint store limpiado. Eliminados=%d. Estado actual: %s (certificados=%d)\n", removed, dir, count)
	return nil
}

func runCLITLSTrustStatus() error {
	lines, err := localTLSTrustStatus()
	if *cliJSONFlag {
		out := map[string]interface{}{"ok": err == nil, "lines": lines}
		if err != nil {
			out["error"] = err.Error()
		}
		return writeJSONOut(out)
	}
	for _, line := range lines {
		fmt.Println(line)
	}
	return err
}

func runCLITLSGenerateCerts() error {
	certFile, keyFile, err := ensureLocalTLSCerts()
	if err != nil {
		return err
	}
	if *cliJSONFlag {
		return writeJSONOut(map[string]interface{}{"ok": true, "certFile": certFile, "keyFile": keyFile})
	}
	fmt.Printf("Certificados generados/listos:\ncert=%s\nkey=%s\n", certFile, keyFile)
	return nil
}

func runCLITLSInstallTrust() error {
	if _, _, err := ensureLocalTLSCerts(); err != nil {
		return err
	}
	lines, err := installLocalTLSTrust()
	if *cliJSONFlag {
		out := map[string]interface{}{"ok": err == nil, "lines": lines}
		if err != nil {
			out["error"] = err.Error()
		}
		return writeJSONOut(out)
	}
	for _, line := range lines {
		fmt.Println(line)
	}
	return err
}

func runCLIVerify(core *CoreService) error {
	in := strings.TrimSpace(*cliInputFlag)
	if in == "" {
		return fmt.Errorf("debe indicar -in para verificar")
	}
	res, err := core.VerifyFile(in, strings.TrimSpace(*cliFormatFlag))
	if err != nil {
		return err
	}
	if *cliJSONFlag {
		out := map[string]interface{}{
			"ok":     true,
			"op":     "verify",
			"input":  in,
			"format": res.Format,
			"result": res.Result,
		}
		return writeJSONOut(out)
	}
	fmt.Println(summarizeVerifyResult(res.Result))
	return nil
}

func runCLISign(core *CoreService, certs []protocol.Certificate, action string) error {
	in := strings.TrimSpace(*cliInputFlag)
	if in == "" {
		return fmt.Errorf("debe indicar -in para firmar")
	}

	cert, err := pickCLICertificate(certs)
	if err != nil {
		return err
	}

	signOpts := buildCLISignOptions(strings.TrimSpace(*cliFormatFlag), in)
	if *cliStrictCompatFlag {
		effectiveFormat := strings.TrimSpace(*cliFormatFlag)
		if normalizeProtocolFormat(effectiveFormat) == "" || strings.EqualFold(effectiveFormat, "auto") {
			effectiveFormat = detectLocalSignFormat(in)
		}
		signOpts = applyStrictCompatDefaults(signOpts, effectiveFormat)
	}
	saveToDisk := !*cliNoSaveFlag
	req := CoreSignRequest{
		FilePath:         in,
		CertificateID:    cert.ID,
		Action:           action,
		Format:           strings.TrimSpace(*cliFormatFlag),
		AllowInvalidPDF:  *cliAllowInvalidPDFFlag,
		SaveToDisk:       false, // Se gestiona aquí para soportar -out personalizado.
		OverwritePolicy:  parseCLIOverwritePolicy(),
		SignatureOptions: signOpts,
	}
	res, err := core.SignFile(req)
	if err != nil {
		return err
	}

	finalOut := strings.TrimSpace(*cliOutputFlag)
	if saveToDisk {
		if finalOut == "" {
			finalOut = buildLocalSignedOutputPath(in, res.Format)
		}
		resolved, renamed, overwrote, err := resolveOutputPathPolicy(finalOut, parseCLIOverwritePolicy())
		if err != nil {
			return err
		}
		raw, err := base64.StdEncoding.DecodeString(res.SignatureB64)
		if err != nil {
			return fmt.Errorf("error decodificando firma para guardar: %w", err)
		}
		if err := os.WriteFile(resolved, raw, 0o644); err != nil {
			return fmt.Errorf("no se pudo guardar salida firmada: %w", err)
		}
		res.OutputPath = resolved
		res.Renamed = renamed
		res.Overwrote = overwrote
	}

	if *cliJSONFlag {
		out := map[string]interface{}{
			"ok":            true,
			"op":            action,
			"input":         in,
			"output":        res.OutputPath,
			"format":        res.Format,
			"certificateId": cert.ID,
			"renamed":       res.Renamed,
			"overwrote":     res.Overwrote,
		}
		if *cliPrintSignatureB64Flag || *cliNoSaveFlag {
			out["signatureB64"] = res.SignatureB64
		}
		return writeJSONOut(out)
	}

	fmt.Printf("Firma completada. Operación=%s Formato=%s Certificado=%s\n", action, res.Format, cert.ID)
	if res.OutputPath != "" {
		fmt.Printf("Salida: %s\n", res.OutputPath)
	}
	if *cliPrintSignatureB64Flag || *cliNoSaveFlag {
		fmt.Printf("SignatureB64: %s\n", res.SignatureB64)
	}
	return nil
}

func buildCLISignOptions(rawFormat string, inputPath string) map[string]interface{} {
	opts := map[string]interface{}{}
	format := normalizeProtocolFormat(strings.TrimSpace(rawFormat))
	if format == "" || format == "auto" {
		format = detectLocalSignFormat(inputPath)
	}
	if *cliVisibleSealFlag && format == "pades" {
		opts["visibleSeal"] = true
		x := clamp01(*cliSealXFlag)
		y := clamp01(*cliSealYFlag)
		w := clamp01(*cliSealWFlag)
		h := clamp01(*cliSealHFlag)
		if strings.EqualFold(strings.TrimSpace(*cliSealLayoutFlag), "footer") {
			m := clamp01(*cliSealFooterMarginFlag)
			if m > 0.2 {
				m = 0.2
			}
			x = m
			y = m
			w = 1.0 - (2.0 * m)
			h = 0.10
		}
		opts["visibleSealRectX"] = x * 595.28
		opts["visibleSealRectY"] = y * 841.89
		opts["visibleSealRectW"] = w * 595.28
		opts["visibleSealRectH"] = h * 841.89
		page := uint32(*cliSealPageFlag)
		if page == 0 {
			page = 1
		}
		opts["page"] = page
	}
	if len(opts) == 0 {
		return nil
	}
	return opts
}

func pickCLICertificate(certs []protocol.Certificate) (protocol.Certificate, error) {
	if len(certs) == 0 {
		return protocol.Certificate{}, fmt.Errorf("no hay certificados disponibles")
	}
	id := strings.TrimSpace(*cliCertIDFlag)
	if id != "" {
		for _, c := range certs {
			if c.ID == id {
				return c, nil
			}
		}
		return protocol.Certificate{}, fmt.Errorf("no se encontró certificado con -cert-id=%s", id)
	}

	if *cliCertIndexFlag >= 0 {
		if *cliCertIndexFlag >= len(certs) {
			return protocol.Certificate{}, fmt.Errorf("cert-index fuera de rango: %d (máximo %d)", *cliCertIndexFlag, len(certs)-1)
		}
		return certs[*cliCertIndexFlag], nil
	}

	contains := strings.ToLower(strings.TrimSpace(*cliCertContainsFlag))
	if contains != "" {
		for _, c := range certs {
			sub := strings.ToLower(certificateBestDisplayName(c))
			nick := strings.ToLower(strings.TrimSpace(c.Nickname))
			serial := strings.ToLower(strings.TrimSpace(c.SerialNumber))
			if strings.Contains(sub, contains) || strings.Contains(nick, contains) || strings.Contains(serial, contains) {
				return c, nil
			}
		}
		return protocol.Certificate{}, fmt.Errorf("no se encontró certificado que contenga: %s", contains)
	}

	return certs[0], nil
}

func parseCLIOverwritePolicy() CoreOverwritePolicy {
	switch strings.ToLower(strings.TrimSpace(*cliOverwriteFlag)) {
	case "force", "overwrite":
		return CoreOverwriteForce
	case "fail", "error":
		return CoreOverwriteFail
	default:
		return CoreOverwriteRename
	}
}

func printCertificatesCLI(certs []protocol.Certificate) {
	if *cliJSONFlag {
		out := make([]map[string]interface{}, 0, len(certs))
		for i, c := range certs {
			out = append(out, map[string]interface{}{
				"index":        i,
				"id":           c.ID,
				"name":         certificateBestDisplayName(c),
				"nickname":     c.Nickname,
				"serialNumber": c.SerialNumber,
				"validFrom":    c.ValidFrom,
				"validTo":      c.ValidTo,
				"canSign":      c.CanSign,
				"signIssue":    c.SignIssue,
				"source":       c.Source,
			})
		}
		_ = writeJSONOut(map[string]interface{}{
			"ok":           true,
			"certificates": out,
		})
		return
	}

	if len(certs) == 0 {
		fmt.Println("No se encontraron certificados.")
		return
	}
	for i, c := range certs {
		canSign := "sí"
		if !c.CanSign {
			canSign = "no"
		}
		name := certificateBestDisplayName(c)
		if strings.TrimSpace(name) == "" {
			name = "(sin nombre)"
		}
		fmt.Printf("[%d] %s\n", i, name)
		fmt.Printf("    id=%s canSign=%s validTo=%s source=%s\n", c.ID, canSign, c.ValidTo, c.Source)
		if strings.TrimSpace(c.SignIssue) != "" {
			fmt.Printf("    signIssue=%s\n", c.SignIssue)
		}
	}
}

func writeJSONOut(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func appendCLIDetailedUsage(out *strings.Builder) {
	out.WriteString("  -cli-help\n")
	out.WriteString("    Muestra ayuda CLI específica con ejemplos.\n")
	out.WriteString("  -ayuda-cli\n")
	out.WriteString("    Alias castellano de -cli-help.\n")
	out.WriteString("  -cli\n")
	out.WriteString("    Ejecuta en modo línea de comandos sin abrir interfaz gráfica.\n")
	out.WriteString("  -modo-cli\n")
	out.WriteString("    Alias castellano de -cli.\n")
	out.WriteString("  -list-certs [-check-certs] [-json]\n")
	out.WriteString("    Lista certificados. Con -check-certs prueba firma CAdES de capacidad.\n")
	out.WriteString("  -op sign|cosign|countersign -in <fichero> (-cert-id <id> | -cert-index <n> | -cert-contains <texto>)\n")
	out.WriteString("    Firma en CLI. Si no se indica certificado, usa el primero disponible.\n")
	out.WriteString("    Alias castellano: -operacion firmar|cofirmar|contrafirmar -entrada <fichero> (-id-certificado|-indice-certificado|-certificado-contiene).\n")
	out.WriteString("  -op verify -in <fichero>\n")
	out.WriteString("    Verifica firma en CLI.\n")
	out.WriteString("    Alias castellano: -operacion verificar -entrada <fichero>.\n")
	out.WriteString("  -op diagnostics-report\n")
	out.WriteString("    Resumen técnico sin GUI: certificados, trust TLS y dominios confiados.\n")
	out.WriteString("    Alias castellano: -operacion informe-diagnostico.\n")
	out.WriteString("  -op domains-list | domains-add -domain <host> | domains-remove -domain <host>\n")
	out.WriteString("    Gestiona whitelist de dominios de firma confiados.\n")
	out.WriteString("    Alias castellano: listar-dominios | anadir-dominio -dominio <host> | eliminar-dominio -dominio <host>.\n")
	out.WriteString("  -op tls-store-status | tls-store-clear | tls-trust-status | tls-generate-certs | tls-install-trust\n")
	out.WriteString("    Gestión no gráfica de certificados y confianza TLS local.\n")
	out.WriteString("    Alias castellano: estado-almacen-tls | limpiar-almacen-tls | estado-confianza-tls | generar-certificados-tls | instalar-confianza-tls.\n")
	out.WriteString("  -out <ruta> | -no-save | -print-signature\n")
	out.WriteString("    Controla salida firmada en disco y/o firma Base64 por stdout.\n")
	out.WriteString("    Alias castellano: -salida <ruta> | -no-guardar | -imprimir-firma.\n")
	out.WriteString("  -overwrite fail|rename|force\n")
	out.WriteString("    Política al existir salida en disco.\n")
	out.WriteString("    Alias castellano: -sobrescribir.\n")
	out.WriteString("  -format auto|pades|cades|xades\n")
	out.WriteString("    Fuerza formato de firma/verificación.\n")
	out.WriteString("    Alias castellano: -formato.\n")
	out.WriteString("  -strict-compat\n")
	out.WriteString("    Aplica defaults Java: algorithm/mode/signatureSubFilter.\n")
	out.WriteString("    Alias castellano: -compatibilidad-estricta.\n")
	out.WriteString("  -allow-invalid-pdf\n")
	out.WriteString("    Permite PDF no válido en PAdES.\n")
	out.WriteString("    Alias castellano: -permitir-pdf-invalido.\n")
	out.WriteString("  -visible-seal [-seal-page N -seal-x X -seal-y Y -seal-w W -seal-h H]\n")
	out.WriteString("    Firma visible en PAdES con coordenadas normalizadas (0..1).\n")
	out.WriteString("    Alias castellano: -sello-visible [-sello-pagina N -sello-x X -sello-y Y -sello-ancho W -sello-alto H].\n")
	out.WriteString("  -seal-layout manual|footer [-seal-footer-margin M]\n")
	out.WriteString("    footer coloca la firma automáticamente abajo del todo.\n")
	out.WriteString("    Alias castellano: -disposicion-sello manual|footer [-margen-inferior-sello M].\n")
	out.WriteString("  -json\n")
	out.WriteString("    Salida estructurada en JSON para automatizaciones.\n")
	out.WriteString("    Alias castellano: -salida-json.\n")
	out.WriteString("  -rest -rest-addr -rest-token -rest-cert-fingerprints -rest-session-ttl\n")
	out.WriteString("    Modo servidor REST local con autenticación por token y/o certificado.\n")
	out.WriteString("    Endpoints protegidos: /health /certificates /sign /verify /diagnostics/report /security/domains /tls/clear-store /tls/trust-status /tls/install-trust /tls/generate-certs.\n")
	out.WriteString("    Alias castellano: -servidor-rest -direccion-rest -token-rest -huellas-cert-rest -ttl-sesion-rest.\n")
}

func writeCLIHelp(out io.Writer, program string) {
	_, _ = fmt.Fprintf(out, "Modo CLI de %s\n\n", program)
	_, _ = fmt.Fprintln(out, "Resumen de opciones:")
	var b strings.Builder
	appendCLIDetailedUsage(&b)
	_, _ = fmt.Fprint(out, b.String())
	_, _ = fmt.Fprintln(out, "")
	_, _ = fmt.Fprintln(out, "Ejemplos:")
	_, _ = fmt.Fprintf(out, "  %s -cli -list-certs\n", program)
	_, _ = fmt.Fprintf(out, "  %s -cli -list-certs -check-certs -json\n", program)
	_, _ = fmt.Fprintf(out, "  %s -cli -op sign -in /ruta/entrada.pdf -cert-index 0\n", program)
	_, _ = fmt.Fprintf(out, "  %s -cli -op sign -in /ruta/entrada.pdf -cert-id <ID> -out /ruta/salida.pdf -overwrite force\n", program)
	_, _ = fmt.Fprintf(out, "  %s -cli -op sign -in /ruta/entrada.pdf -cert-contains \"apellidos nombre\" -strict-compat\n", program)
	_, _ = fmt.Fprintf(out, "  %s -cli -op sign -in /ruta/entrada.pdf -cert-index 0 -visible-seal -seal-page 1 -seal-x 0.62 -seal-y 0.04 -seal-w 0.34 -seal-h 0.12\n", program)
	_, _ = fmt.Fprintf(out, "  %s -cli -op verify -in /ruta/firmado.pdf\n", program)
	_, _ = fmt.Fprintf(out, "  %s -cli -op sign -in /ruta/entrada.pdf -cert-index 0 -no-save -print-signature -json\n", program)
	_, _ = fmt.Fprintf(out, "  %s -cli -op sign -in /ruta/entrada.pdf -cert-index 0 -visible-seal -seal-layout footer\n", program)
	_, _ = fmt.Fprintf(out, "  %s -cli -op diagnostics-report -json\n", program)
	_, _ = fmt.Fprintf(out, "  %s -cli -op domains-add -domain firma.ejemplo.gob.es\n", program)
	_, _ = fmt.Fprintf(out, "  %s -cli -op tls-trust-status\n", program)
	_, _ = fmt.Fprintf(out, "  %s -modo-cli -operacion firmar -entrada /ruta/entrada.pdf -indice-certificado 0 -formato pades\n", program)
	_, _ = fmt.Fprintf(out, "  %s -modo-cli -operacion informe-diagnostico -salida-json\n", program)
	_, _ = fmt.Fprintln(out, "")
	_, _ = fmt.Fprintln(out, "Modo REST (API local + consola web):")
	_, _ = fmt.Fprintf(out, "  %s -rest -rest-addr 127.0.0.1:63118 -rest-token secreto\n", program)
	_, _ = fmt.Fprintf(out, "  %s -rest -rest-addr 127.0.0.1:63118 -rest-cert-fingerprints <sha256>\n", program)
	_, _ = fmt.Fprintf(out, "  %s -servidor-rest -direccion-rest 127.0.0.1:63118 -token-rest secreto\n", program)
	_, _ = fmt.Fprintln(out, "")
	_, _ = fmt.Fprintln(out, "Flujo de autenticación por certificado (challenge/verify):")
	_, _ = fmt.Fprintln(out, "  1) Obtener reto: GET /auth/challenge")
	_, _ = fmt.Fprintln(out, "  2) Firmar challengeB64 con la clave privada del certificado")
	_, _ = fmt.Fprintln(out, "  3) Enviar challengeId + signatureB64 + certificatePEM a POST /auth/verify")
	_, _ = fmt.Fprintln(out, "  4) Usar sessionToken devuelto como Bearer para endpoints protegidos")
	_, _ = fmt.Fprintln(out, "")
	_, _ = fmt.Fprintln(out, "Endpoints REST:")
	_, _ = fmt.Fprintln(out, "  Públicos:   GET /, GET/POST /auth/challenge, POST /auth/verify")
	_, _ = fmt.Fprintln(out, "  Protegidos: GET /health")
	_, _ = fmt.Fprintln(out, "              GET /certificates?check=0|1")
	_, _ = fmt.Fprintln(out, "              POST /sign")
	_, _ = fmt.Fprintln(out, "              POST /verify")
	_, _ = fmt.Fprintln(out, "              GET /diagnostics/report")
	_, _ = fmt.Fprintln(out, "              GET/POST/DELETE /security/domains")
	_, _ = fmt.Fprintln(out, "              POST /tls/clear-store")
	_, _ = fmt.Fprintln(out, "              GET /tls/trust-status")
	_, _ = fmt.Fprintln(out, "              POST /tls/install-trust")
	_, _ = fmt.Fprintln(out, "              POST /tls/generate-certs")
	_, _ = fmt.Fprintln(out, "")
	_, _ = fmt.Fprintln(out, "Ejemplo curl rápido (token):")
	_, _ = fmt.Fprintln(out, "  curl -H 'Authorization: Bearer secreto' http://127.0.0.1:63118/health")
	_, _ = fmt.Fprintln(out, "  curl -H 'Authorization: Bearer secreto' http://127.0.0.1:63118/diagnostics/report")
	_, _ = fmt.Fprintln(out, "  curl -X POST -H 'Authorization: Bearer secreto' -H 'Content-Type: application/json' \\")
	_, _ = fmt.Fprintln(out, "    -d '{\"domain\":\"firma.ejemplo.gob.es\"}' http://127.0.0.1:63118/security/domains")
	_, _ = fmt.Fprintln(out, "  curl -X POST -H 'Authorization: Bearer secreto' http://127.0.0.1:63118/tls/clear-store")
	_, _ = fmt.Fprintln(out, "  curl -H 'Authorization: Bearer secreto' http://127.0.0.1:63118/tls/trust-status")
	_, _ = fmt.Fprintln(out, "")
	_, _ = fmt.Fprintln(out, "Consola web REST:")
	_, _ = fmt.Fprintln(out, "  http://127.0.0.1:63118/")
	_, _ = fmt.Fprintln(out, "")
	_, _ = fmt.Fprintln(out, "Documentación completa: docs/REST_API.md")
}
