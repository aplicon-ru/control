package deploy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthcheck_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := Healthcheck(context.Background(), srv.Client(), srv.URL); err != nil {
		t.Fatalf("Healthcheck: %v", err)
	}
}

func TestHealthcheck_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	if err := Healthcheck(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Fatal("Healthcheck: want error for 503, got nil")
	}
}

func TestHealthcheck_ConnectionRefused(t *testing.T) {
	if err := Healthcheck(context.Background(), http.DefaultClient, "http://127.0.0.1:1"); err == nil {
		t.Fatal("Healthcheck: want error for unreachable host, got nil")
	}
}

func TestHealthcheck_MalformedURL(t *testing.T) {
	if err := Healthcheck(context.Background(), http.DefaultClient, "://not-a-url"); err == nil {
		t.Fatal("Healthcheck: want error for malformed URL, got nil")
	}
}

func TestResolveHealthcheckURL_RewritesLocalhost(t *testing.T) {
	got, err := resolveHealthcheckURL("http://localhost:8001/health", "10.0.0.5")
	if err != nil {
		t.Fatalf("resolveHealthcheckURL: %v", err)
	}
	if got != "http://10.0.0.5:8001/health" {
		t.Fatalf("resolveHealthcheckURL: got %q", got)
	}
}

func TestResolveHealthcheckURL_Rewrites127001(t *testing.T) {
	got, err := resolveHealthcheckURL("http://127.0.0.1:8001/health", "10.0.0.5")
	if err != nil {
		t.Fatalf("resolveHealthcheckURL: %v", err)
	}
	if got != "http://10.0.0.5:8001/health" {
		t.Fatalf("resolveHealthcheckURL: got %q", got)
	}
}

func TestResolveHealthcheckURL_LeavesRealHostAlone(t *testing.T) {
	got, err := resolveHealthcheckURL("https://testikon.example.com/health", "10.0.0.5")
	if err != nil {
		t.Fatalf("resolveHealthcheckURL: %v", err)
	}
	if got != "https://testikon.example.com/health" {
		t.Fatalf("resolveHealthcheckURL: got %q, want unchanged", got)
	}
}

func TestResolveHealthcheckURL_NoPort(t *testing.T) {
	got, err := resolveHealthcheckURL("http://localhost/health", "10.0.0.5")
	if err != nil {
		t.Fatalf("resolveHealthcheckURL: %v", err)
	}
	if got != "http://10.0.0.5/health" {
		t.Fatalf("resolveHealthcheckURL: got %q", got)
	}
}

func TestResolveHealthcheckURL_Malformed(t *testing.T) {
	if _, err := resolveHealthcheckURL("://not-a-url", "10.0.0.5"); err == nil {
		t.Fatal("resolveHealthcheckURL: want error for malformed URL, got nil")
	}
}
