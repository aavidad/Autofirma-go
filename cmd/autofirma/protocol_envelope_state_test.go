package main

import (
	"net/url"
	"testing"
)

func TestParseAutoFirmaXMLUpdatesSessionStateFromEnvelope(t *testing.T) {
	state := &ProtocolState{
		FileID:        "retrieve123",
		RequestID:     "retrieve123",
		ActiveWaiting: false,
		Params:        make(url.Values),
	}

	xmlData := []byte(`<sign>
		<e k="id" v="upload456"/>
		<e k="stservlet" v="https%3A%2F%2Fafirmasignature.sededgsfp.gob.es%2Fafirma-signature-storage%2FStorageService"/>
		<e k="aw" v="true"/>
		<e k="key" v="12345678"/>
		<e k="format" v="CAdES"/>
		<e k="dat" v="YWJj"/>
	</sign>`)

	data, format, err := parseAutoFirmaXML(xmlData, state)
	if err != nil {
		t.Fatalf("parseAutoFirmaXML devolvió error: %v", err)
	}
	if string(data) != "abc" {
		t.Fatalf("datos inesperados: %q", string(data))
	}
	if format != "CAdES" {
		t.Fatalf("formato inesperado: %q", format)
	}
	if state.FileID != "upload456" || state.RequestID != "upload456" {
		t.Fatalf("ids inesperados: file=%q request=%q", state.FileID, state.RequestID)
	}
	if !state.ActiveWaiting {
		t.Fatal("ActiveWaiting debería haberse actualizado desde el XML")
	}
	if state.Key != "12345678" {
		t.Fatalf("key inesperada: %q", state.Key)
	}
	if got := state.STServlet; got != "https://afirmasignature.sededgsfp.gob.es/afirma-signature-storage/StorageService" {
		t.Fatalf("STServlet inesperado: %q", got)
	}
}

func TestTryParseAfirmaEnvelopeRehydratesBatchSessionState(t *testing.T) {
	state := &ProtocolState{
		FileID:        "retrieve999",
		RequestID:     "retrieve999",
		STServlet:     "https://afirmasignature.sededgsfp.gob.es/old/StorageService",
		ActiveWaiting: false,
		Key:           "00000000",
		Params:        make(url.Values),
	}
	state.Params.Set("fileid", "retrieve999")
	state.Params.Set("rtservlet", "https://afirmasignature.sededgsfp.gob.es/afirma-signature-storage/RetrieveService")

	raw := []byte(`<batch>
		<e k="id" v="upload777"/>
		<e k="stservlet" v="https%3A%2F%2Fafirmasignature.sededgsfp.gob.es%2Fafirma-signature-storage%2FStorageService"/>
		<e k="aw" v="true"/>
		<e k="key" v="87654321"/>
		<e k="jsonbatch" v="true"/>
		<e k="dat" v="e30="/>
	</batch>`)

	if !tryParseAfirmaEnvelope(raw, state) {
		t.Fatal("debería haberse reconocido el envelope afirma")
	}
	if state.FileID != "upload777" || state.RequestID != "upload777" {
		t.Fatalf("ids inesperados: file=%q request=%q", state.FileID, state.RequestID)
	}
	if !state.ActiveWaiting {
		t.Fatal("ActiveWaiting debería haberse actualizado desde el envelope")
	}
	if state.Key != "87654321" {
		t.Fatalf("key inesperada: %q", state.Key)
	}
	if got := state.STServlet; got != "https://afirmasignature.sededgsfp.gob.es/afirma-signature-storage/StorageService" {
		t.Fatalf("STServlet inesperado: %q", got)
	}
	if got := state.Params.Get("jsonbatch"); got != "true" {
		t.Fatalf("jsonbatch inesperado en params: %q", got)
	}
}
