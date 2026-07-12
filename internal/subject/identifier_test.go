package subject

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIdentifierHeaderPriorityAndNoPlaintext(t *testing.T) {
	t.Setenv(HMACKeyEnvironment, "0123456789abcdef0123456789abcdef")
	identifier, err := NewIdentifier(IdentifierConfig{})
	if err != nil {
		t.Fatal(err)
	}
	status := identifier.Status()
	if !status.Stable || status.Source != KeySourceEnvironment || status.Degraded {
		t.Fatalf("Status() = %#v", status)
	}

	const bearer = "bearer-plaintext-canary"
	const apiKey = "x-api-key-plaintext-canary"
	headers := http.Header{
		"authorization": []string{"Bearer " + bearer}, // intentionally non-canonical key
		"x-api-key":     []string{apiKey},
	}
	identity := identifier.FromHeaders(headers)
	if identity.Source != SourceAuthorization {
		t.Fatalf("source = %q", identity.Source)
	}
	if identity.Hash != expectedHMAC("0123456789abcdef0123456789abcdef", bearer) {
		t.Fatalf("hash = %q", identity.Hash)
	}
	encoded := identity.Hash + identity.Source.String()
	if strings.Contains(encoded, bearer) || strings.Contains(encoded, apiKey) {
		t.Fatalf("Identity retained plaintext: %#v", identity)
	}

	identity = identifier.FromHeaders(http.Header{"X-Api-Key": []string{apiKey}})
	if identity.Source != SourceAPIKey || identity.Hash != expectedHMAC("0123456789abcdef0123456789abcdef", apiKey) {
		t.Fatalf("x-api-key identity = %#v", identity)
	}

	// Unsupported Authorization schemes are not treated as API key material;
	// the supported x-api-key fallback remains available.
	identity = identifier.FromHeaders(http.Header{
		"Authorization": []string{"Basic should-not-be-hashed"},
		"X-API-Key":     []string{apiKey},
	})
	if identity.Source != SourceAPIKey || identity.Hash != expectedHMAC("0123456789abcdef0123456789abcdef", apiKey) {
		t.Fatalf("Basic fallback identity = %#v", identity)
	}

	identity = identifier.FromHeaders(nil)
	if identity.Source != SourceAnonymous || identity.Hash == "" || strings.Contains(identity.Hash, "anonymous") {
		t.Fatalf("anonymous identity = %#v", identity)
	}
}

func TestIdentifierSecretFilePermissions(t *testing.T) {
	t.Setenv(HMACKeyEnvironment, "")
	t.Setenv(HMACKeyFileEnvironment, "")
	dir := t.TempDir()
	path := filepath.Join(dir, "hmac.key")
	if err := os.WriteFile(path, []byte("abcdef0123456789abcdef0123456789\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	identifier, err := NewIdentifier(IdentifierConfig{SecretFile: path})
	if err != nil {
		t.Fatalf("NewIdentifier(0600 file): %v", err)
	}
	if got := identifier.Status(); !got.Stable || got.Source != KeySourceFile || got.Degraded {
		t.Fatalf("file Status() = %#v", got)
	}
	if got := identifier.FromHeaders(http.Header{"X-API-Key": []string{"secret"}}).Hash; got != expectedHMAC("abcdef0123456789abcdef0123456789", "secret") {
		t.Fatalf("file-backed hash = %q", got)
	}

	for _, mode := range []os.FileMode{0o640, 0o604, 0o644} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := NewIdentifier(IdentifierConfig{SecretFile: path}); err == nil || !strings.Contains(err.Error(), "0600") {
			t.Fatalf("NewIdentifier(%04o file) error = %v", mode, err)
		}
	}
}

func TestIdentifierSecretFileEnvironment(t *testing.T) {
	t.Setenv(HMACKeyEnvironment, "")
	path := filepath.Join(t.TempDir(), "hmac.key")
	if err := os.WriteFile(path, []byte("fedcba9876543210fedcba9876543210"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(HMACKeyFileEnvironment, path)
	identifier, err := NewIdentifier(IdentifierConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if got := identifier.Status(); !got.Stable || got.Source != KeySourceFile {
		t.Fatalf("file environment Status() = %#v", got)
	}
}

func TestIdentifierSecretFileRejectsUnsafeFiles(t *testing.T) {
	t.Setenv(HMACKeyEnvironment, "")
	t.Setenv(HMACKeyFileEnvironment, "")

	t.Run("symbolic link", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target.key")
		if err := os.WriteFile(target, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "link.key")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symbolic links are unavailable: %v", err)
		}
		if _, err := NewIdentifier(IdentifierConfig{SecretFile: link}); err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("NewIdentifier(symbolic link) error = %v", err)
		}
	})

	t.Run("directory", func(t *testing.T) {
		if _, err := NewIdentifier(IdentifierConfig{SecretFile: t.TempDir()}); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("NewIdentifier(directory) error = %v", err)
		}
	})

	t.Run("too large", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "large.key")
		if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, maximumSecretBytes+1), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewIdentifier(IdentifierConfig{SecretFile: path}); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("NewIdentifier(oversized file) error = %v", err)
		}
	})
}

func TestIdentifierRandomFallbackIsExplicitlyDegraded(t *testing.T) {
	t.Setenv(HMACKeyEnvironment, "")
	t.Setenv(HMACKeyFileEnvironment, "")
	first, err := NewIdentifier(IdentifierConfig{Random: bytes.NewReader(bytes.Repeat([]byte{0x11}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewIdentifier(IdentifierConfig{Random: bytes.NewReader(bytes.Repeat([]byte{0x22}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	if got := first.Status(); got.Stable || !got.Degraded || got.Source != KeySourceProcessRandom || got.Warning == "" {
		t.Fatalf("fallback Status() = %#v", got)
	}
	headers := http.Header{"Authorization": []string{"Bearer same-key"}}
	one := first.FromHeaders(headers)
	if one != first.FromHeaders(headers) {
		t.Fatal("one process did not produce a stable identity")
	}
	if one.Hash == second.FromHeaders(headers).Hash {
		t.Fatal("separate process-random keys produced the same identity")
	}
}

func expectedHMAC(key, value string) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(value))
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
}
