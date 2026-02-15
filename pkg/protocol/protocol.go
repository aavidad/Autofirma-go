// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package protocol

// Request from Chrome extension
type Request struct {
	RequestID        interface{}            `json:"requestId"`
	Action           string                 `json:"action"`
	CertificateID    string                 `json:"certificateId,omitempty"`
	Data             string                 `json:"data,omitempty"` // Base64 encoded
	PIN              string                 `json:"pin,omitempty"`
	Format           string                 `json:"format,omitempty"` // pades, xades, cades
	SignatureOptions map[string]interface{} `json:"signatureOptions,omitempty"`
	OriginalData     string                 `json:"originalData,omitempty"`
	SignatureData    string                 `json:"signatureData,omitempty"`
}

// Response to Chrome extension
type Response struct {
	RequestID    string        `json:"requestId"`
	Success      bool          `json:"success"`
	Error        string        `json:"error,omitempty"`
	Certificates []Certificate `json:"certificates,omitempty"`
	Signature    string        `json:"signature,omitempty"`    // Base64 encoded
	SignatureLen int           `json:"signatureLen,omitempty"` // Total length for integrity check
	Result       *VerifyResult `json:"result,omitempty"`
	Chunk        int           `json:"chunk"`                 // Current chunk index (0-based) - MUST always serialize
	TotalChunks  int           `json:"totalChunks,omitempty"` // Total number of chunks
}

// VerifyResult signature verification result
type VerifyResult struct {
	Valid       bool   `json:"valid"`
	SignerName  string `json:"signerName,omitempty"`
	SignerEmail string `json:"signerEmail,omitempty"`
	SignerOrg   string `json:"signerOrg,omitempty"`
	Timestamp   string `json:"timestamp,omitempty"`
	Format      string `json:"format,omitempty"`
	Algorithm   string `json:"algorithm,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// Certificate information
type Certificate struct {
	ID           string            `json:"id"`
	Subject      map[string]string `json:"subject"`
	Issuer       map[string]string `json:"issuer"`
	SerialNumber string            `json:"serialNumber"`
	ValidFrom    string            `json:"validFrom"`
	ValidTo      string            `json:"validTo"`
	Fingerprint  string            `json:"fingerprint"`
	Source       string            `json:"source"` // system, dnie, smartcard
	PEM          string            `json:"pem"`
	Nickname     string            `json:"nickname,omitempty"` // NSS nickname for signing
	CanSign      bool              `json:"canSign"`
	SignIssue    string            `json:"signIssue,omitempty"`
	Content      []byte            `json:"-"` // Raw DER content (internal use, not serialized)
}
