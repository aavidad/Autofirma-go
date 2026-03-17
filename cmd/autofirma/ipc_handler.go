package main

import (
	"autofirma-host/pkg/certstore"
	"bufio"
	"encoding/base64"
	"encoding/json"
	"log"
	"net"
	"os"
	"strings"
)

type ipcRequest struct {
	Action string          `json:"action"`
	Params json.RawMessage `json:"params"`
}

type ipcResponse struct {
	Action string      `json:"action,omitempty"`
	OK     bool        `json:"ok"`
	Error  string      `json:"error,omitempty"`
	Data   interface{} `json:"data,omitempty"`
}

func runIPCServer(socketPath string, core *CoreService) error {
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" {
		socketPath = "/tmp/autofirma_ipc.sock"
	}
	os.Remove(socketPath)

	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer l.Close()
	os.Chmod(socketPath, 0600)

	log.Printf("[IPC] Servidor activo en socket Unix: %s", socketPath)

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("[IPC] Error aceptando conexion: %v", err)
			continue
		}
		go handleIPCConnection(conn, core)
	}
}

func handleIPCConnection(conn net.Conn, core *CoreService) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Bytes()
		var req ipcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			sendIPCResponse(conn, ipcResponse{OK: false, Error: "invalid json"})
			continue
		}
		resp := processIPCRequest(req, core)
		resp.Action = req.Action // Añadir el contexto de la acción
		sendIPCResponse(conn, resp)
	}
}

func processIPCRequest(req ipcRequest, core *CoreService) ipcResponse {
	switch req.Action {

	// ── Certificados ──────────────────────────────────────────────────────────
	case "certificates", "certificados":
		certs, err := core.LoadCertificates()
		if err != nil {
			return ipcResponse{OK: false, Error: err.Error()}
		}
		return ipcResponse{OK: true, Data: certs}

	case "check_certificates", "certificados_probar":
		certs, _ := core.LoadCertificates()
		checked, okCount, failCount := core.CheckCertificates(certs)
		return ipcResponse{
			OK: true,
			Data: map[string]interface{}{
				"certificates": checked,
				"okCount":      okCount,
				"failCount":    failCount,
			},
		}

	case "import_certificate", "certificados_importar":
		var params struct {
			P12B64   string `json:"p12B64"`
			Password string `json:"password"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return ipcResponse{OK: false, Error: "invalid params"}
		}
		if params.P12B64 == "" {
			return ipcResponse{OK: false, Error: "p12B64 is required"}
		}
		data, err := base64.StdEncoding.DecodeString(params.P12B64)
		if err != nil {
			return ipcResponse{OK: false, Error: "invalid base64"}
		}
		tmpFile, err := os.CreateTemp("", "autofirma-import-*.p12")
		if err != nil {
			return ipcResponse{OK: false, Error: "failed to create temp file"}
		}
		defer os.Remove(tmpFile.Name())
		if _, err := tmpFile.Write(data); err != nil {
			tmpFile.Close()
			return ipcResponse{OK: false, Error: "failed to write temp file"}
		}
		tmpFile.Close()

		if err := certstore.ImportP12ToSystem(tmpFile.Name(), params.Password); err != nil {
			return ipcResponse{OK: false, Error: err.Error()}
		}
		return ipcResponse{OK: true, Data: "Certificado importado correctamente"}

	case "install_public_roots", "confianza_instalar":
		lines, err := installPublicAdminRoots()
		if err != nil {
			return ipcResponse{OK: false, Error: err.Error(), Data: lines}
		}
		return ipcResponse{OK: true, Data: lines}

	// ── Firma ─────────────────────────────────────────────────────────────────
	case "sign", "firmar":
		var params restSignRequest
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return ipcResponse{OK: false, Error: "invalid params"}
		}
		normalizeSignRequestAliases(&params)
		action := strings.ToLower(strings.TrimSpace(params.Action))
		if action == "" {
			action = "sign"
		}
		if action != "sign" && action != "cosign" && action != "countersign" {
			return ipcResponse{OK: false, Error: "action no soportada"}
		}
		signOpts := buildSignOptionsForREST(params)
		if params.StrictCompat {
			effectiveFormat := strings.TrimSpace(params.Format)
			if normalizeProtocolFormat(effectiveFormat) == "" || strings.EqualFold(effectiveFormat, "auto") {
				effectiveFormat = detectLocalSignFormat(strings.TrimSpace(params.InputPath))
			}
			signOpts = applyStrictCompatDefaults(signOpts, effectiveFormat)
		}
		saveToDisk := true
		if params.SaveToDisk != nil {
			saveToDisk = *params.SaveToDisk
		}
		coreReq := CoreSignRequest{
			FilePath:         strings.TrimSpace(params.InputPath),
			OutputPath:       strings.TrimSpace(params.OutputPath),
			Action:           action,
			Format:           strings.TrimSpace(params.Format),
			AllowInvalidPDF:  params.AllowInvalidPDF,
			SaveToDisk:       saveToDisk,
			OverwritePolicy:  parseOverwritePolicyREST(params.Overwrite),
			SignatureOptions: signOpts,
		}
		if params.CertificateID != "" {
			coreReq.CertificateID = params.CertificateID
		} else {
			certs, _ := core.LoadCertificates()
			if params.CertificateIndex >= 0 && params.CertificateIndex < len(certs) {
				coreReq.CertificateID = certs[params.CertificateIndex].ID
			}
		}
		res, err := core.SignFile(coreReq)
		if err != nil {
			return ipcResponse{OK: false, Error: err.Error()}
		}
		return ipcResponse{OK: true, Data: res}

	// ── Verificacion ──────────────────────────────────────────────────────────
	case "verify", "verificar":
		var params struct {
			InputPath string `json:"inputPath"`
			Format    string `json:"format"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return ipcResponse{OK: false, Error: "invalid params"}
		}
		res, err := core.VerifyFile(params.InputPath, params.Format)
		if err != nil {
			return ipcResponse{OK: false, Error: err.Error()}
		}
		return ipcResponse{OK: true, Data: res.Result}

	case "pdf_preview", "pdf_previsualizar":
		var params struct {
			Path string `json:"path"`
			Page int    `json:"page"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return ipcResponse{OK: false, Error: "invalid params"}
		}
		b64, width, height, err := core.GeneratePdfPreview(params.Path, params.Page)
		if err != nil {
			return ipcResponse{OK: false, Error: err.Error()}
		}
		return ipcResponse{OK: true, Data: map[string]interface{}{
			"data":   b64,
			"width":  width,
			"height": height,
		}}

	// ── Health check ──────────────────────────────────────────────────────────
	case "health", "salud":
		return ipcResponse{OK: true, Data: "OK"}

	// ── Diagnósticos y SOPORTE ───────────────────────────────────────────────
	case "tls_diagnostics":
		lines, err := localTLSTrustStatus()
		if err != nil {
			return ipcResponse{OK: false, Error: err.Error()}
		}
		return ipcResponse{OK: true, Data: strings.Join(lines, "\n")}

	case "export_diagnostic":
		certs, _ := core.LoadCertificates()
		canSign := 0
		for _, c := range certs {
			if c.CanSign {
				canSign++
			}
		}
		dir, count := endpointTrustStoreStatus()
		lines, _ := localTLSTrustStatus()
		return ipcResponse{OK: true, Data: map[string]interface{}{
			"certificates": len(certs),
			"canSign":      canSign,
			"storeDir":     dir,
			"storeCount":   count,
			"trustLines":   strings.Join(lines, "\n"),
		}}

	case "clear_tls_trust":
		removed, err := clearEndpointTrustStore()
		if err != nil {
			return ipcResponse{OK: false, Error: err.Error()}
		}
		return ipcResponse{OK: true, Data: removed}

	// ── Gestion del servicio de usuario ───────────────────────────────────────
	case "service_status", "servicio_estado":
		mgr, err := GetServiceManager()
		if err != nil {
			return ipcResponse{OK: false, Error: err.Error()}
		}
		return ipcResponse{OK: true, Data: mgr.Status()}

	case "service_install", "servicio_instalar":
		var params struct {
			IpcSocket string `json:"ipcSocket"`
		}
		if len(req.Params) > 2 {
			_ = json.Unmarshal(req.Params, &params)
		}
		socket := params.IpcSocket
		if socket == "" {
			socket = "/tmp/autofirma_ipc.sock"
		}
		mgr, err := GetServiceManager()
		if err != nil {
			return ipcResponse{OK: false, Error: err.Error()}
		}
		if err := mgr.Install(socket); err != nil {
			return ipcResponse{OK: false, Error: err.Error()}
		}
		return ipcResponse{OK: true, Data: "Servicio instalado correctamente"}

	case "service_uninstall", "servicio_desinstalar":
		mgr, err := GetServiceManager()
		if err != nil {
			return ipcResponse{OK: false, Error: err.Error()}
		}
		if err := mgr.Uninstall(); err != nil {
			return ipcResponse{OK: false, Error: err.Error()}
		}
		return ipcResponse{OK: true, Data: "Servicio desinstalado correctamente"}

	case "service_start", "servicio_iniciar":
		mgr, err := GetServiceManager()
		if err != nil {
			return ipcResponse{OK: false, Error: err.Error()}
		}
		if err := mgr.Start(); err != nil {
			return ipcResponse{OK: false, Error: err.Error()}
		}
		return ipcResponse{OK: true, Data: "Servicio iniciado"}

	case "service_stop", "servicio_parar":
		mgr, err := GetServiceManager()
		if err != nil {
			return ipcResponse{OK: false, Error: err.Error()}
		}
		if err := mgr.Stop(); err != nil {
			return ipcResponse{OK: false, Error: err.Error()}
		}
		return ipcResponse{OK: true, Data: "Servicio detenido"}

	// ── Configuración (Settings) ──────────────────────────────────────────────
	case "get_settings":
		s := LoadUserSettings()
		return ipcResponse{OK: true, Data: s}

	case "save_settings":
		var s UserSettings
		if err := json.Unmarshal(req.Params, &s); err != nil {
			return ipcResponse{OK: false, Error: "invalid params for save_settings"}
		}
		if err := SaveUserSettings(s); err != nil {
			return ipcResponse{OK: false, Error: err.Error()}
		}
		return ipcResponse{OK: true, Data: s}

	default:
		return ipcResponse{OK: false, Error: "unknown action: " + req.Action}
	}
}

func sendIPCResponse(conn net.Conn, resp ipcResponse) {
	data, _ := json.Marshal(resp)
	conn.Write(append(data, '\n'))
}
