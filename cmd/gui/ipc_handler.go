package main

import (
	"bufio"
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
	OK    bool        `json:"ok"`
	Error string      `json:"error,omitempty"`
	Data  interface{} `json:"data,omitempty"`
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
	os.Chmod(socketPath, 0666)

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

	// ── Firma ─────────────────────────────────────────────────────────────────
	case "sign", "firmar":
		var params restSignRequest
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return ipcResponse{OK: false, Error: "invalid params"}
		}
		coreReq := CoreSignRequest{
			FilePath:        params.InputPath,
			OutputPath:      params.OutputPath,
			Format:          params.Format,
			SaveToDisk:      true,
			OverwritePolicy: CoreOverwriteForce,
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

	// ── Health check ──────────────────────────────────────────────────────────
	case "health", "salud":
		return ipcResponse{OK: true, Data: "OK"}

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

	default:
		return ipcResponse{OK: false, Error: "unknown action: " + req.Action}
	}
}

func sendIPCResponse(conn net.Conn, resp ipcResponse) {
	data, _ := json.Marshal(resp)
	conn.Write(append(data, '\n'))
}
