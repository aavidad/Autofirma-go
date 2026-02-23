// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget/material"
)

type TLSEndpointDiagResult struct {
	Endpoint   string
	Host       string
	Estado     string
	Detalle    string
	Sugerencia string
	Subject    string
	Issuer     string
	NeedCert   bool
}

func (ui *UI) layoutTLSEndpointManager(gtx layout.Context) layout.Dimensions {
	storeDir, storeCount := endpointTrustStoreStatus()
	storeMsg := fmt.Sprintf("Almacén TLS local: %d certificado(s).", storeCount)
	if strings.TrimSpace(storeDir) != "" {
		storeMsg += " Ruta: " + storeDir
	}
	return layout.UniformInset(unit.Dp(6)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				lbl := material.Body1(ui.Theme, "Gestor TLS de endpoints de firma")
				return lbl.Layout(gtx)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				msg := material.Caption(ui.Theme, "Comprueba cadena TLS (incluye caducidad) e instala certificados remotos cuando falten.")
				return msg.Layout(gtx)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				msg := material.Caption(ui.Theme, storeMsg)
				return msg.Layout(gtx)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Spacer{Height: unit.Dp(6)}.Layout(gtx)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						if ui.BtnRunTLSDiagnostics.Clicked(gtx) && !ui.TLSDiagRunning {
							go ui.runTLSEndpointDiagnostics()
						}
						txt := "Diagnóstico TLS endpoints"
						if ui.TLSDiagRunning {
							txt = "Diagnosticando TLS..."
						}
						btn := material.Button(ui.Theme, &ui.BtnRunTLSDiagnostics, txt)
						return layout.UniformInset(unit.Dp(4)).Layout(gtx, btn.Layout)
					}),
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						if ui.BtnImportTLSCert.Clicked(gtx) {
							go ui.importTLSCertificateFromDialog()
						}
						btn := material.Button(ui.Theme, &ui.BtnImportTLSCert, "Instalar certificado .crt/.cer")
						return layout.UniformInset(unit.Dp(4)).Layout(gtx, btn.Layout)
					}),
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						if ui.BtnClearTLSDiagnostics.Clicked(gtx) {
							ui.TLSDiagResults = nil
							ui.Window.Invalidate()
						}
						btn := material.Button(ui.Theme, &ui.BtnClearTLSDiagnostics, "Limpiar")
						return layout.UniformInset(unit.Dp(4)).Layout(gtx, btn.Layout)
					}),
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						if ui.BtnClearTLSStore.Clicked(gtx) {
							go ui.clearTLSEndpointStore()
						}
						btn := material.Button(ui.Theme, &ui.BtnClearTLSStore, "Vaciar almacén TLS local")
						return layout.UniformInset(unit.Dp(4)).Layout(gtx, btn.Layout)
					}),
				)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if len(ui.TLSDiagResults) == 0 {
					msg := material.Caption(ui.Theme, "Sin resultados aún. Ejecuta el diagnóstico para los endpoints de la sesión actual.")
					return layout.UniformInset(unit.Dp(6)).Layout(gtx, msg.Layout)
				}
				maxH := gtx.Dp(unit.Dp(180))
				if maxH < 120 {
					maxH = 120
				}
				gtx.Constraints.Min.Y = maxH
				gtx.Constraints.Max.Y = maxH
				return material.List(ui.Theme, &ui.TLSDiagList).Layout(gtx, len(ui.TLSDiagResults), func(gtx layout.Context, index int) layout.Dimensions {
					if index < 0 || index >= len(ui.TLSDiagResults) {
						return layout.Dimensions{}
					}
					r := ui.TLSDiagResults[index]
					lines := []string{
						fmt.Sprintf("[%s] %s", r.Estado, r.Endpoint),
						"Detalle: " + r.Detalle,
					}
					if strings.TrimSpace(r.Subject) != "" {
						lines = append(lines, "Subject: "+r.Subject)
					}
					if strings.TrimSpace(r.Issuer) != "" {
						lines = append(lines, "Issuer: "+r.Issuer)
					}
					if strings.TrimSpace(r.Sugerencia) != "" {
						lines = append(lines, "Posible solución: "+r.Sugerencia)
					}
					lbl := material.Body2(ui.Theme, strings.Join(lines, "\n"))
					return layout.UniformInset(unit.Dp(6)).Layout(gtx, lbl.Layout)
				})
			}),
		)
	})
}

func (ui *UI) clearTLSEndpointStore() {
	removed, err := clearEndpointTrustStore()
	if err != nil {
		ui.StatusMsg = withSolution(
			"No se pudo vaciar el almacén TLS local: "+summarizeServerBody(err.Error()),
			"Revisa permisos de escritura en ~/.config/AutofirmaDipgra/certs/endpoints.",
		)
		ui.Window.Invalidate()
		return
	}
	ui.StatusMsg = fmt.Sprintf("Almacén TLS local vaciado correctamente (%d certificado(s) eliminados).", removed)
	ui.Window.Invalidate()
}

func (ui *UI) runTLSEndpointDiagnostics() {
	if ui.TLSDiagRunning {
		return
	}
	ui.TLSDiagRunning = true
	ui.HealthStatus = appendMultilineStatus(ui.HealthStatus, "Gestor TLS: iniciando diagnóstico de endpoints...", 14000)
	ui.Window.Invalidate()
	defer func() {
		ui.TLSDiagRunning = false
		ui.Window.Invalidate()
	}()

	endpoints := collectSigningTLSEndpoints(ui.Protocol)
	if len(endpoints) == 0 {
		ui.StatusMsg = withSolution(
			"No hay endpoints HTTPS de firma en la sesión actual para diagnosticar TLS.",
			"Lanza una firma web primero y vuelve a ejecutar este diagnóstico.",
		)
		return
	}

	results := make([]TLSEndpointDiagResult, 0, len(endpoints))
	for _, ep := range endpoints {
		results = append(results, diagnoseTLSEndpoint(ep))
	}
	ui.TLSDiagResults = results

	var failed int
	for _, r := range results {
		if r.Estado != "OK" {
			failed++
		}
	}
	if failed == 0 {
		ui.StatusMsg = "Diagnóstico TLS completado: todos los endpoints de firma validan correctamente."
	} else {
		ui.StatusMsg = withSolution(
			fmt.Sprintf("Diagnóstico TLS completado con incidencias (%d/%d endpoints).", failed, len(results)),
			"Revisa el detalle en 'Gestor TLS de endpoints de firma' y, si falta cadena, instala el certificado intermedio/raíz oficial.",
		)
	}
}

func collectSigningTLSEndpoints(state *ProtocolState) []string {
	out := make([]string, 0, 6)
	seen := map[string]bool{}
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		u, err := url.Parse(raw)
		if err != nil || u == nil || !strings.EqualFold(u.Scheme, "https") || strings.TrimSpace(u.Hostname()) == "" {
			return
		}
		k := strings.ToLower(strings.TrimSpace(u.String()))
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, u.String())
	}

	if state != nil {
		add(state.STServlet)
		add(state.RTServlet)
		for _, key := range []string{"batchpresignerurl", "batchpostsignerurl", "batchpresignerUrl", "batchpostsignerUrl"} {
			add(state.Params.Get(key))
		}
	}

	sort.Strings(out)
	return out
}

func diagnoseTLSEndpoint(endpoint string) TLSEndpointDiagResult {
	res := TLSEndpointDiagResult{
		Endpoint: endpoint,
		Estado:   "ERROR",
		Detalle:  "Error de diagnóstico no clasificado.",
	}
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil {
		res.Detalle = "URL inválida: " + summarizeServerBody(err.Error())
		res.Sugerencia = "Revisa la URL configurada para STServlet/RTServlet."
		return res
	}
	host := strings.TrimSpace(u.Hostname())
	res.Host = host
	port := strings.TrimSpace(u.Port())
	if port == "" {
		port = "443"
	}
	target := net.JoinHostPort(host, port)

	dialer := net.Dialer{Timeout: 8 * time.Second}
	tconn, err := dialer.Dial("tcp", target)
	if err != nil {
		res.Detalle = "Sin conectividad TCP: " + summarizeServerBody(err.Error())
		res.Sugerencia = "Revisa red/proxy/firewall y salida al puerto " + port + "."
		return res
	}
	_ = tconn.Close()

	cfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // Se verifica manualmente con SystemCertPool para poder diagnosticar detalle.
		MinVersion:         tls.VersionTLS12,
	}
	conn, err := tls.DialWithDialer(&dialer, "tcp", target, cfg)
	if err != nil {
		res.Detalle = "Fallo de handshake TLS: " + summarizeServerBody(err.Error())
		res.Sugerencia = "Comprueba fecha/hora del sistema, proxy HTTPS y cadena de certificados del servidor."
		return res
	}
	defer conn.Close()

	cs := conn.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		res.Detalle = "El servidor no presentó certificados TLS."
		res.Sugerencia = "Revisa configuración TLS del endpoint remoto."
		return res
	}

	leaf := cs.PeerCertificates[0]
	res.Subject = strings.TrimSpace(leaf.Subject.String())
	res.Issuer = strings.TrimSpace(leaf.Issuer.String())

	now := time.Now()
	if now.Before(leaf.NotBefore) {
		res.Estado = "ERROR"
		res.NeedCert = true
		res.Detalle = fmt.Sprintf("Certificado aún no válido hasta %s.", leaf.NotBefore.Format(time.RFC3339))
		res.Sugerencia = "Corrige fecha/hora del sistema o espera a la validez oficial del nuevo certificado."
		return res
	}
	if now.After(leaf.NotAfter) {
		res.Estado = "ERROR"
		res.NeedCert = true
		res.Detalle = fmt.Sprintf("Certificado TLS caducado el %s.", leaf.NotAfter.Format("2006-01-02"))
		res.Sugerencia = certRenewHint(leaf)
		return res
	}

	roots, _ := x509.SystemCertPool()
	if roots == nil {
		roots = x509.NewCertPool()
	}
	appendEndpointTrustStoreCerts(roots)
	inter := x509.NewCertPool()
	for i := 1; i < len(cs.PeerCertificates); i++ {
		inter.AddCert(cs.PeerCertificates[i])
	}
	_, verifyErr := leaf.Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now,
	})
	if verifyErr == nil {
		res.Estado = "OK"
		res.Detalle = "Cadena TLS válida en este equipo."
		res.Sugerencia = ""
		return res
	}

	res.Estado = "ERROR"
	res.NeedCert = true
	res.Detalle = "Cadena TLS no válida: " + summarizeServerBody(verifyErr.Error())
	res.Sugerencia = mapTLSVerifyErrorToHint(verifyErr, leaf)
	return res
}

func certRenewHint(leaf *x509.Certificate) string {
	issuing := leaf.IssuingCertificateURL
	if len(issuing) > 0 {
		return "Obtén el certificado renovado desde la CA emisora o esta URL de cadena: " + strings.Join(issuing, ", ")
	}
	return "Obtén el certificado renovado desde la entidad emisora (FNMT/CA corporativa o sede de la Administración) e impórtalo en el sistema."
}

func mapTLSVerifyErrorToHint(err error, leaf *x509.Certificate) string {
	var unknownAuthErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthErr) {
		if len(leaf.IssuingCertificateURL) > 0 {
			return "Falta confianza en la cadena. Descarga e instala el intermedio/raíz oficial desde: " + strings.Join(leaf.IssuingCertificateURL, ", ")
		}
		return "Falta confianza en la cadena. Instala certificado intermedio/raíz oficial de la entidad emisora."
	}
	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return "El nombre del certificado no coincide con el dominio. Revisa endpoint y certificado del servidor."
	}
	var invalidErr x509.CertificateInvalidError
	if errors.As(err, &invalidErr) {
		if invalidErr.Reason == x509.Expired {
			return certRenewHint(leaf)
		}
		return "Certificado no válido para este uso. Reinstala cadena oficial y revisa políticas de validación."
	}
	return "Revisa cadena TLS, proxy HTTPS y almacenes de confianza del sistema."
}

func (ui *UI) importTLSCertificateFromDialog() {
	paths, canceled, err := protocolLoadDialog("", "crt,cer,pem,der", false)
	if err != nil {
		ui.StatusMsg = withSolution("No se pudo abrir selector de certificado: "+summarizeServerBody(err.Error()), "Reintenta e indica un fichero .crt/.cer/.pem/.der válido.")
		ui.Window.Invalidate()
		return
	}
	if canceled || len(paths) == 0 {
		ui.StatusMsg = "Instalación de certificado TLS cancelada."
		ui.Window.Invalidate()
		return
	}
	selected := strings.TrimSpace(paths[0])
	if selected == "" {
		ui.StatusMsg = withSolution("Ruta de certificado vacía.", "Selecciona un certificado válido para continuar.")
		ui.Window.Invalidate()
		return
	}

	cert, err := loadCertificateFromFile(selected)
	if err != nil {
		ui.StatusMsg = withSolution("No se pudo leer el certificado: "+summarizeServerBody(err.Error()), "Asegúrate de que el fichero contiene un certificado X.509 válido.")
		ui.Window.Invalidate()
		return
	}

	lines, installErr := installTrustedCertificateForCurrentOS(selected, cert)
	if saved, savedLines, saveErr := saveEndpointCertificates("manual", []*x509.Certificate{cert}); saveErr != nil {
		lines = append(lines, "[TLS] Almacén local: error guardando certificado: "+summarizeServerBody(saveErr.Error()))
	} else {
		lines = append(lines, savedLines...)
		if saved > 0 {
			lines = append(lines, "[TLS] Almacén local actualizado correctamente.")
		}
	}
	ui.HealthStatus = appendMultilineStatus(ui.HealthStatus, strings.Join(lines, "\n"), 14000)
	if installErr != nil {
		ui.StatusMsg = withSolution("No se pudo instalar el certificado en los almacenes disponibles: "+summarizeServerBody(installErr.Error()), "Si requiere permisos elevados, ejecuta la app con permisos adecuados o instala manualmente el certificado.")
	} else {
		ui.StatusMsg = "Certificado instalado en almacenes disponibles. Repite el diagnóstico TLS para confirmar."
	}
	ui.Window.Invalidate()
}

func loadCertificateFromFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var block *pem.Block
	rest := data
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" && len(block.Bytes) > 0 {
			return x509.ParseCertificate(block.Bytes)
		}
		if len(rest) == 0 {
			break
		}
	}
	return x509.ParseCertificate(data)
}

func installTrustedCertificateForCurrentOS(certPath string, cert *x509.Certificate) ([]string, error) {
	lines := []string{
		"[TLS] Instalación de certificado iniciada: " + certPath,
		"[TLS] Subject: " + strings.TrimSpace(cert.Subject.String()),
		"[TLS] Issuer: " + strings.TrimSpace(cert.Issuer.String()),
	}

	switch runtime.GOOS {
	case "windows":
		if out, err := exec.Command("certutil", "-user", "-addstore", "-f", "Root", certPath).CombinedOutput(); err != nil {
			return lines, fmt.Errorf("certutil Root(CurrentUser): %v (%s)", err, strings.TrimSpace(string(out)))
		}
		if out, err := exec.Command("certutil", "-user", "-addstore", "-f", "CA", certPath).CombinedOutput(); err != nil {
			return lines, fmt.Errorf("certutil CA(CurrentUser): %v (%s)", err, strings.TrimSpace(string(out)))
		}
		lines = append(lines, "[TLS] Windows: instalado en CurrentUser\\Root y CurrentUser\\CA.")
		return lines, nil

	case "darwin":
		keychain := macOSLoginKeychainPath()
		if out, err := exec.Command("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", keychain, certPath).CombinedOutput(); err != nil {
			return lines, fmt.Errorf("security add-trusted-cert: %v (%s)", err, strings.TrimSpace(string(out)))
		}
		lines = append(lines, "[TLS] macOS: instalado en login keychain.")
		return lines, nil

	default:
		installed := 0
		if _, err := exec.LookPath("certutil"); err == nil {
			dbs := discoverNSSDBs()
			for _, db := range dbs {
				nick := "Autofirma TLS " + cert.SerialNumber.String()
				out, addErr := exec.Command("certutil", "-d", "sql:"+db, "-A", "-t", "C,,", "-n", nick, "-i", certPath).CombinedOutput()
				if addErr != nil {
					msg := strings.ToLower(strings.TrimSpace(string(out)))
					if strings.Contains(msg, "already exists") || strings.Contains(msg, "sec_error_adding_cert") {
						lines = append(lines, "[TLS] NSS ya contenía certificado en "+db)
						installed++
						continue
					}
					lines = append(lines, "[TLS] NSS error en "+db+": "+summarizeServerBody(addErr.Error()))
					continue
				}
				lines = append(lines, "[TLS] NSS instalado en "+db)
				installed++
			}
		} else {
			lines = append(lines, "[TLS] certutil no disponible: no se pudo instalar en NSS de usuario.")
		}

		if os.Geteuid() == 0 {
			target := "/usr/local/share/ca-certificates/autofirma-extra-" + sanitizeCertFilename(cert.SerialNumber.String()) + ".crt"
			if err := copyFile(certPath, target, 0o644); err != nil {
				return lines, err
			}
			if _, err := exec.LookPath("update-ca-certificates"); err == nil {
				out, updErr := exec.Command("update-ca-certificates").CombinedOutput()
				if updErr != nil {
					return lines, fmt.Errorf("update-ca-certificates: %v (%s)", updErr, strings.TrimSpace(string(out)))
				}
				lines = append(lines, "[TLS] Sistema: certificado instalado y bundle actualizado.")
				return lines, nil
			}
			lines = append(lines, "[TLS] Sistema: certificado copiado, pero no se encontró update-ca-certificates.")
			return lines, nil
		}

		lines = append(lines, "[TLS] Sistema global no modificado (requiere root).")
		lines = append(lines, "Comando sugerido: sudo cp "+shellQuote(certPath)+" /usr/local/share/ca-certificates/autofirma-extra.crt && sudo update-ca-certificates")
		if installed > 0 {
			return lines, nil
		}
		return lines, fmt.Errorf("no se pudo instalar en almacenes de usuario (NSS no disponible o sin perfiles)")
	}
}

func sanitizeCertFilename(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "cert"
	}
	r := strings.NewReplacer("/", "-", "\\", "-", ":", "-", " ", "-", "\t", "-", "\n", "-")
	v = r.Replace(v)
	if len(v) > 48 {
		v = v[:48]
	}
	return v
}

func shellQuote(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(v, "'", "'\"'\"'") + "'"
}
