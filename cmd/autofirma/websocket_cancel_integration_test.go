package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func freeTCPPortForTest(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("no se pudo reservar puerto libre: %v", err)
	}
	defer ln.Close()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok || addr.Port <= 0 {
		t.Fatalf("dirección TCP inválida: %v", ln.Addr())
	}
	return addr.Port
}

func TestWebSocketStopSendsCancelToClientDuringCallbackSign(t *testing.T) {
	port := freeTCPPortForTest(t)
	s := NewWebSocketServer([]int{port}, "sess-cancel-test", nil)
	startedSign := make(chan struct{}, 1)
	releaseSign := make(chan struct{})
	s.signFunc = func(_ *ProtocolState, _ string) (SignatureResult, error) {
		select {
		case startedSign <- struct{}{}:
		default:
		}
		<-releaseSign
		return SignatureResult{}, errProtocolUserCanceled
	}

	if err := s.Start(); err != nil {
		t.Fatalf("no se pudo iniciar servidor websocket: %v", err)
	}
	defer func() {
		close(releaseSign)
		s.Stop()
	}()

	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test local loopback self-signed
	}
	wsURL := fmt.Sprintf("wss://127.0.0.1:%d/", port)
	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("no se pudo conectar al WSS local: %v", err)
	}
	defer conn.Close()

	if err := conn.WriteMessage(websocket.TextMessage, []byte("afirma://sign?idsession=sess-cancel-test&op=sign&properties=Zg==")); err != nil {
		t.Fatalf("no se pudo enviar solicitud sign: %v", err)
	}

	select {
	case <-startedSign:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout esperando inicio de signFunc")
	}

	// Simula cierre de app mientras el usuario está en el selector/flujo de firma.
	s.Stop()

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("no se recibió respuesta tras Stop(): %v", err)
	}
	if string(msg) != "CANCEL" {
		t.Fatalf("respuesta inesperada tras Stop(): %q", string(msg))
	}
}
