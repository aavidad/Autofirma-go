// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import "testing"

func TestParseProtocolURI_AliasAndRequiredParams(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantErr bool
		check   func(t *testing.T, p *ProtocolState)
	}{
		{
			name: "direct names",
			uri:  "afirma://sign?fileid=abc123&rtservlet=https%3A%2F%2Fr.example%2FRetrieveService&stservlet=https%3A%2F%2Fs.example%2FStorageService&format=CAdES",
			check: func(t *testing.T, p *ProtocolState) {
				if p.FileID != "abc123" || p.RequestID != "abc123" {
					t.Fatalf("id/requestID inesperado: file=%q req=%q", p.FileID, p.RequestID)
				}
				if p.RTServlet == "" || p.STServlet == "" {
					t.Fatalf("servlets vacios rt=%q st=%q", p.RTServlet, p.STServlet)
				}
				if p.SignFormat != "CAdES" {
					t.Fatalf("format inesperado: %q", p.SignFormat)
				}
			},
		},
		{
			name: "alias names",
			uri:  "afirma://sign?id=xyz789&retrieveservlet=https%3A%2F%2Fr.example%2FRetrieveService&storageservlet=https%3A%2F%2Fs.example%2FStorageService&key=secreto",
			check: func(t *testing.T, p *ProtocolState) {
				if p.FileID != "xyz789" || p.RequestID != "xyz789" {
					t.Fatalf("id/requestID inesperado: file=%q req=%q", p.FileID, p.RequestID)
				}
				if p.Key != "secreto" {
					t.Fatalf("key inesperada: %q", p.Key)
				}
				if p.RTServlet == "" || p.STServlet == "" {
					t.Fatalf("servlets vacios rt=%q st=%q", p.RTServlet, p.STServlet)
				}
			},
		},
		{
			name: "legacy camelCase aliases and action in path",
			uri:  "afirma:///sign?fileId=req42&retrieveServlet=https%3A%2F%2Fr.example%2FRetrieveService&storageServlet=https%3A%2F%2Fs.example%2FStorageService&signFormat=PAdES&idSession=abc",
			check: func(t *testing.T, p *ProtocolState) {
				if p.Action != "sign" {
					t.Fatalf("action inesperada: %q", p.Action)
				}
				if p.FileID != "req42" || p.RequestID != "req42" {
					t.Fatalf("id/requestID inesperado: file=%q req=%q", p.FileID, p.RequestID)
				}
				if p.RTServlet == "" || p.STServlet == "" {
					t.Fatalf("servlets vacios rt=%q st=%q", p.RTServlet, p.STServlet)
				}
				if p.SignFormat != "PAdES" {
					t.Fatalf("signFormat inesperado: %q", p.SignFormat)
				}
				if got := p.Params.Get("idSession"); got != "abc" {
					t.Fatalf("idSession no presente en params: %q", got)
				}
			},
		},
		{
			name: "local sign flow allows missing rtservlet",
			uri:  "afirma://sign?id=local1&stservlet=https%3A%2F%2Fs.example%2FStorageService",
			check: func(t *testing.T, p *ProtocolState) {
				if p.RTServlet != "" {
					t.Fatalf("rtservlet deberia ir vacio, recibido=%q", p.RTServlet)
				}
				if p.STServlet == "" || p.FileID != "local1" {
					t.Fatalf("datos inesperados st=%q id=%q", p.STServlet, p.FileID)
				}
			},
		},
		{
			name: "legacy action alias firmar maps to sign",
			uri:  "afirma://firmar?id=alias1&stservlet=https%3A%2F%2Fs.example%2FStorageService",
			check: func(t *testing.T, p *ProtocolState) {
				if p.Action != "sign" {
					t.Fatalf("action alias no normalizada, obtenido=%q", p.Action)
				}
			},
		},
		{
			name: "action from query op fallback",
			uri:  "afirma://?op=sign&id=alias2&stservlet=https%3A%2F%2Fs.example%2FStorageService",
			check: func(t *testing.T, p *ProtocolState) {
				if p.Action != "sign" {
					t.Fatalf("action desde op no normalizada, obtenido=%q", p.Action)
				}
			},
		},
		{
			name:    "insufficient params",
			uri:     "afirma://sign?foo=bar",
			wantErr: true,
		},
		{
			name: "websocket save without servlets is allowed",
			uri:  "afirma://save?op=save&idsession=s1&title=Guardar&dat=QUJD",
			check: func(t *testing.T, p *ProtocolState) {
				if p.Action != "save" {
					t.Fatalf("action inesperada: %q", p.Action)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParseProtocolURI(tc.uri)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("se esperaba error y no hubo")
				}
				return
			}
			if err != nil {
				t.Fatalf("error inesperado: %v", err)
			}
			if p == nil {
				t.Fatalf("protocol state nil")
			}
			if tc.check != nil {
				tc.check(t, p)
			}
		})
	}
}
