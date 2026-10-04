package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestEmbeddedWebSocketPath(t *testing.T) {
	s, err := NewServer(&Options{DontListen: true, NoLog: true, NoSigs: true, Authorization: "embedded-test"})
	if err != nil {
		t.Fatal(err)
	}
	s.Start()
	defer s.Shutdown()
	if !s.ReadyForConnections(time.Second) {
		t.Fatal("embedded server not ready")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/omtm/agent", s.HandleWebSocket)
	h := httptest.NewServer(mux)
	defer h.Close()
	endpoint := "ws" + strings.TrimPrefix(h.URL, "http")
	if c, err := nats.Connect(endpoint, nats.ProxyPath("/api/v1/omtm/agent"), nats.NoReconnect(), nats.Timeout(time.Second)); err == nil {
		c.Close()
		t.Fatal("unauthenticated connection accepted")
	}
	c, err := nats.Connect(endpoint, nats.ProxyPath("/api/v1/omtm/agent"), nats.Token("embedded-test"), nats.NoReconnect(), nats.Timeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sub, err := c.SubscribeSync("embedded.test")
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Publish("embedded.test", []byte("ok")); err != nil {
		t.Fatal(err)
	}
	m, err := sub.NextMsg(time.Second)
	if err != nil || string(m.Data) != "ok" {
		t.Fatalf("round trip failed: %v", err)
	}
	r, err := http.Get(h.URL + "/api/v1/omtm/agent")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid handshake status: %d", r.StatusCode)
	}
}
