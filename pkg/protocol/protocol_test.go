// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package protocol

import (
	"encoding/json"
	"testing"
)

func TestResponseChunkAlwaysSerialized(t *testing.T) {
	r := Response{RequestID: "1", Success: true}

	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var obj map[string]any
	if err = json.Unmarshal(b, &obj); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if _, ok := obj["chunk"]; !ok {
		t.Fatalf("expected 'chunk' field to be serialized")
	}
}

func TestResponseOmitsTotalChunksWhenZero(t *testing.T) {
	r := Response{RequestID: "1", Success: true, Chunk: 0, TotalChunks: 0}

	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var obj map[string]any
	if err = json.Unmarshal(b, &obj); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if _, ok := obj["totalChunks"]; ok {
		t.Fatalf("did not expect 'totalChunks' when value is zero")
	}
}

func TestRequestIDSupportsStringAndNumber(t *testing.T) {
	var req Request

	err := json.Unmarshal([]byte(`{"requestId":"abc","action":"ping"}`), &req)
	if err != nil {
		t.Fatalf("string requestId unmarshal failed: %v", err)
	}
	if req.RequestID != "abc" {
		t.Fatalf("unexpected requestId value: %#v", req.RequestID)
	}

	err = json.Unmarshal([]byte(`{"requestId":12,"action":"ping"}`), &req)
	if err != nil {
		t.Fatalf("number requestId unmarshal failed: %v", err)
	}
	if _, ok := req.RequestID.(float64); !ok {
		t.Fatalf("expected numeric requestId to decode as float64, got %#v", req.RequestID)
	}
}
