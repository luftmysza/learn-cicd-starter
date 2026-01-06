package auth

import (
	"net/http"
	"testing"
	"errors"
)

func TestGetAPIKey_Success(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey super-secret-key")

	key, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if key != "super-secret-key" {
		t.Fatalf("expected key %q, got %q", "super-secret-key", key)
	}
}

func TestGetAPIKey_NoHeader(t *testing.T) {
	headers := http.Header{} // no Authorization set

	key, err := GetAPIKey(headers)
	if err == nil {
		t.Fatalf("expected error, got nil (key=%q)", key)
	}

	if !errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer something") // wrong scheme

	key, err := GetAPIKey(headers)
	if err == nil {
		t.Fatalf("expected error for malformed header, got nil (key=%q)", key)
	}
}

