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
)

func isCLIModeRequested() bool {
	if *cliModeFlag || *cliHelpFlag {
		return true
	}
	if strings.TrimSpace(*cliOperationFlag) != "" {
		return true
	}
	return *cliListCertsFlag || *cliCheckCertsFlag
}

func runCLIMode() error {
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

	op := strings.ToLower(strings.TrimSpace(*cliOperationFlag))
	if op == "" {
		return nil
	}

	switch op {
	case "verify":
		return runCLIVerify(core)
	case "sign", "cosign", "countersign":
		return runCLISign(core, certs, op)
	default:
		return fmt.Errorf("operación no soportada en CLI: %s (use sign|cosign|countersign|verify)", op)
	}
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
		opts["visibleSealRectX"] = clamp01(*cliSealXFlag) * 595.28
		opts["visibleSealRectY"] = clamp01(*cliSealYFlag) * 841.89
		opts["visibleSealRectW"] = clamp01(*cliSealWFlag) * 595.28
		opts["visibleSealRectH"] = clamp01(*cliSealHFlag) * 841.89
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
	out.WriteString("  -cli\n")
	out.WriteString("    Ejecuta en modo línea de comandos sin abrir interfaz gráfica.\n")
	out.WriteString("  -list-certs [-check-certs] [-json]\n")
	out.WriteString("    Lista certificados. Con -check-certs prueba firma CAdES de capacidad.\n")
	out.WriteString("  -op sign|cosign|countersign -in <fichero> (-cert-id <id> | -cert-index <n> | -cert-contains <texto>)\n")
	out.WriteString("    Firma en CLI. Si no se indica certificado, usa el primero disponible.\n")
	out.WriteString("  -op verify -in <fichero>\n")
	out.WriteString("    Verifica firma en CLI.\n")
	out.WriteString("  -out <ruta> | -no-save | -print-signature\n")
	out.WriteString("    Controla salida firmada en disco y/o firma Base64 por stdout.\n")
	out.WriteString("  -overwrite fail|rename|force\n")
	out.WriteString("    Política al existir salida en disco.\n")
	out.WriteString("  -format auto|pades|cades|xades\n")
	out.WriteString("    Fuerza formato de firma/verificación.\n")
	out.WriteString("  -strict-compat\n")
	out.WriteString("    Aplica defaults Java: algorithm/mode/signatureSubFilter.\n")
	out.WriteString("  -allow-invalid-pdf\n")
	out.WriteString("    Permite PDF no válido en PAdES.\n")
	out.WriteString("  -visible-seal [-seal-page N -seal-x X -seal-y Y -seal-w W -seal-h H]\n")
	out.WriteString("    Firma visible en PAdES con coordenadas normalizadas (0..1).\n")
	out.WriteString("  -json\n")
	out.WriteString("    Salida estructurada en JSON para automatizaciones.\n")
	out.WriteString("  -rest -rest-addr -rest-token -rest-cert-fingerprints -rest-session-ttl\n")
	out.WriteString("    Modo servidor REST local con autenticación por token y/o certificado.\n")
	out.WriteString("    Endpoints protegidos: /health /certificates /sign /verify /diagnostics/report /security/domains /tls/clear-store /tls/trust-status /tls/install-trust /tls/generate-certs.\n")
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
	_, _ = fmt.Fprintln(out, "")
	_, _ = fmt.Fprintln(out, "Modo REST (API local + consola web):")
	_, _ = fmt.Fprintf(out, "  %s -rest -rest-addr 127.0.0.1:63118 -rest-token secreto\n", program)
	_, _ = fmt.Fprintf(out, "  %s -rest -rest-addr 127.0.0.1:63118 -rest-cert-fingerprints <sha256>\n", program)
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
