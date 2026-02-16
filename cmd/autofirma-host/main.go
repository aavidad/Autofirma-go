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

	log.Println("=== AutoFirma Native Host Started ===")

	for {
		payload, err := readNativeMessage(os.Stdin)
		if err != nil {
			if err == io.EOF {
				log.Println("EOF received, exiting")
				break
			}
			log.Printf("Error reading native message: %v", err)
			break
		}

		responses := handleMessage(payload)
		for _, resp := range responses {
			if err := writeNativeMessage(os.Stdout, resp); err != nil {
				log.Printf("Error writing native response: %v", err)
				return
			}
			// Reduce risk of buffering issues in browser pipe on very large responses.
			time.Sleep(25 * time.Millisecond)
		}
	}

	log.Println("=== AutoFirma Native Host Stopped ===")
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
		resp := errorResponse("", "Invalid request format")
		encoded, _ := json.Marshal(resp)
		return [][]byte{encoded}
	}

	reqID := normalizeRequestID(req.RequestID)
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
			resp = errorResponse(reqID, "Missing data or certificateId")
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
		resp = errorResponse(reqID, "Unknown action: "+req.Action)
	}

	if len(resp.Signature) <= signatureChunkSize {
		encoded, _ := json.Marshal(resp)
		return [][]byte{encoded}
	}

	totalLen := len(resp.Signature)
	totalChunks := (totalLen + signatureChunkSize - 1) / signatureChunkSize
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
			fallback, _ := json.Marshal(errorResponse(reqID, "Internal chunking error"))
			return [][]byte{fallback}
		}
		parts = append(parts, encoded)
	}
	return parts
}
