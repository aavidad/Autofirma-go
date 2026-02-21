// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

type restServiceStatusResponse struct {
	OK     bool          `json:"ok"`
	Status ServiceStatus `json:"status"`
}

type restServiceActionResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

type restServiceInstallRequest struct {
	IpcSocket string `json:"ipcSocket"`
	SocketIPC string `json:"socketIpc"` // alias ES
}

func (s *restServer) handleServiceStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, restError{OK: false, Error: "method not allowed"})
		return
	}
	mgr, err := GetServiceManager()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, restServiceStatusResponse{OK: true, Status: mgr.Status()})
}

func (s *restServer) handleServiceInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, restError{OK: false, Error: "method not allowed"})
		return
	}
	var req restServiceInstallRequest
	// body is optional; ignore parse error
	_ = decodeJSONBody(r, &req)

	socket := strings.TrimSpace(req.IpcSocket)
	if socket == "" {
		socket = strings.TrimSpace(req.SocketIPC)
	}
	if socket == "" {
		socket = "/tmp/autofirma_ipc.sock"
	}

	mgr, err := GetServiceManager()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: err.Error()})
		return
	}
	if err := mgr.Install(socket); err != nil {
		writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, restServiceActionResponse{OK: true, Message: "Servicio instalado y activado correctamente"})
}

func (s *restServer) handleServiceUninstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		writeJSON(w, http.StatusMethodNotAllowed, restError{OK: false, Error: "method not allowed"})
		return
	}
	mgr, err := GetServiceManager()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: err.Error()})
		return
	}
	if err := mgr.Uninstall(); err != nil {
		writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, restServiceActionResponse{OK: true, Message: "Servicio desinstalado correctamente"})
}

func (s *restServer) handleServiceStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, restError{OK: false, Error: "method not allowed"})
		return
	}
	mgr, err := GetServiceManager()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: err.Error()})
		return
	}
	if err := mgr.Start(); err != nil {
		writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, restServiceActionResponse{OK: true, Message: "Servicio iniciado"})
}

func (s *restServer) handleServiceStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, restError{OK: false, Error: "method not allowed"})
		return
	}
	mgr, err := GetServiceManager()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: err.Error()})
		return
	}
	if err := mgr.Stop(); err != nil {
		writeJSON(w, http.StatusInternalServerError, restError{OK: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, restServiceActionResponse{OK: true, Message: "Servicio detenido"})
}

// decodeJSONBody is a helper to decode JSON ignoring errors on empty body.
func decodeJSONBody(r *http.Request, v interface{}) error {
	if r.Body == nil || r.ContentLength == 0 {
		return nil
	}
	defer r.Body.Close()
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}
