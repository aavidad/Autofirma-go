// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"autofirma-host/pkg/applog"
	"autofirma-host/pkg/certstore"
	"autofirma-host/pkg/protocol"
	"autofirma-host/pkg/signer"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

const signatureChunkSize = 512 * 1024

func main() {
	logPath, err := applog.Init("autofirma-host")
	if err != nil {
		log.Printf("No se pudo inicializar logging persistente: %v", err)
	} else {
		log.Printf("Logging inicializado en: %s", logPath)
	}

	log.Println("=== AutoFirma Native Host Iniciado ===")

	for {
		payload, err := readNativeMessage(os.Stdin)
		if err != nil {
			if err == io.EOF {
				log.Println("EOF recibido, saliendo")
				break
			}
			log.Printf("Error leyendo mensaje nativo: %v", err)
			break
		}
		log.Printf("[Host] Mensaje nativo recibido: %s", applog.BytesMeta("payload", payload))

		responses := handleMessage(payload)
		for _, resp := range responses {
			if err := writeNativeMessage(os.Stdout, resp); err != nil {
				log.Printf("Error escribiendo respuesta nativa: %v", err)
				return
			}
			// Reduce risk of buffering issues in browser pipe on very large responses.
			time.Sleep(25 * time.Millisecond)
		}
	}

	log.Println("=== AutoFirma Native Host Detenido ===")
}

func readNativeMessage(r io.Reader) ([]byte, error) {
	var length uint32
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return nil, err
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func writeNativeMessage(w io.Writer, payload []byte) error {
	if err := binary.Write(w, binary.LittleEndian, uint32(len(payload))); err != nil {
		return err
	}
	if _, err := w.Write(payload); err != nil {
		return err
	}
	if f, ok := w.(interface{ Flush() error }); ok {
		_ = f.Flush()
	}
	return nil
}

func normalizeRequestID(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return fmt.Sprintf("%.0f", t)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}

func errorResponse(reqID, msg string) protocol.Response {
	return protocol.Response{
		RequestID: reqID,
		Success:   false,
		Error:     msg,
		Chunk:     0,
	}
}

func handleMessage(data []byte) [][]byte {
	var req protocol.Request
	if err := json.Unmarshal(data, &req); err != nil {
		log.Printf("[Host] Solicitud JSON inválida: %s err=%v", applog.BytesMeta("payload", data), err)
		resp := errorResponse("", "Formato de solicitud inválido")
		encoded, _ := json.Marshal(resp)
		return [][]byte{encoded}
	}

	reqID := normalizeRequestID(req.RequestID)
	log.Printf("[Host] Request: id=%s action=%s cert=%s format=%s pin_set=%t opts=%s data=%s orig=%s sig=%s",
		applog.MaskID(reqID),
		req.Action,
		applog.MaskID(req.CertificateID),
		req.Format,
		strings.TrimSpace(req.PIN) != "",
		applog.OptionKeys(req.SignatureOptions),
		applog.SecretMeta("data", req.Data),
		applog.SecretMeta("originalData", req.OriginalData),
		applog.SecretMeta("signatureData", req.SignatureData),
	)
	resp := protocol.Response{
		RequestID: reqID,
		Chunk:     0,
	}

	switch req.Action {
	case "ping":
		resp.Success = true

	case "getCertificates":
		certs, err := certstore.GetSystemCertificates()
		if err != nil {
			resp = errorResponse(reqID, err.Error())
			break
		}
		resp.Success = true
		resp.Certificates = certs

	case "sign":
		if req.Data == "" || req.CertificateID == "" {
			resp = errorResponse(reqID, "Faltan datos o certificateId")
			break
		}
		signature, err := signer.SignData(req.Data, req.CertificateID, req.PIN, req.Format, req.SignatureOptions)
		if err != nil {
			resp = errorResponse(reqID, err.Error())
			break
		}
		resp.Success = true
		resp.Signature = signature
		resp.SignatureLen = len(signature)

	case "verify":
		result, err := signer.VerifyData(req.OriginalData, req.SignatureData, req.Format)
		if err != nil {
			resp = errorResponse(reqID, err.Error())
			break
		}
		resp.Success = true
		resp.Result = result

	default:
		resp = errorResponse(reqID, "Acción desconocida: "+req.Action)
	}

	if len(resp.Signature) <= signatureChunkSize {
		encoded, _ := json.Marshal(resp)
		log.Printf("[Host] Response: id=%s action=%s success=%t err=%q certs=%d signature=%s chunking=single",
			applog.MaskID(reqID), req.Action, resp.Success, resp.Error, len(resp.Certificates),
			applog.SecretMeta("signature", resp.Signature))
		return [][]byte{encoded}
	}

	totalLen := len(resp.Signature)
	totalChunks := (totalLen + signatureChunkSize - 1) / signatureChunkSize
	log.Printf("[Host] Response chunking: id=%s action=%s success=%t total_signature_len=%d total_chunks=%d",
		applog.MaskID(reqID), req.Action, resp.Success, totalLen, totalChunks)
	parts := make([][]byte, 0, totalChunks)
	for i := 0; i < totalChunks; i++ {
		start := i * signatureChunkSize
		end := start + signatureChunkSize
		if end > totalLen {
			end = totalLen
		}

		chunkResp := resp
		chunkResp.Chunk = i
		chunkResp.TotalChunks = totalChunks
		chunkResp.Signature = resp.Signature[start:end]

		encoded, err := json.Marshal(chunkResp)
		if err != nil {
			fallback, _ := json.Marshal(errorResponse(reqID, "Error interno de fragmentación"))
			return [][]byte{fallback}
		}
		parts = append(parts, encoded)
	}
	return parts
}
