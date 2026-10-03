package main

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/chud-lori/milog/internal/config"
)

func TestStreamHandler_outlivesWriteTimeout(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{LogDir: dir, AlertStateDir: dir, Refresh: 1}

	srv := httptest.NewUnstartedServer(streamHandler(cfg))
	srv.Config.WriteTimeout = 300 * time.Millisecond
	srv.Start()
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(srv.URL + "?refresh=1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	// The second summary arrives ~1s in, well past the 300ms WriteTimeout.
	events := 0
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for events < 2 && sc.Scan() {
		if strings.HasPrefix(sc.Text(), "event: summary") {
			events++
		}
	}
	if events < 2 {
		t.Fatalf("stream closed after %d summary events (err=%v); want 2", events, sc.Err())
	}
}
