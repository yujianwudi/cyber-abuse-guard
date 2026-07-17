package classifier

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

var classifierPolicySourceFiles = []string{
	"go.mod",
	"go.sum",
	"internal/classifier/behavior.go",
	"internal/classifier/classifier.go",
	"internal/classifier/matcher.go",
	"internal/classifier/meta_override.go",
	"internal/classifier/meta_override_structure.go",
	"internal/classifier/normalize.go",
	"internal/classifier/policy_identity_test.go",
	"internal/classifier/roles.go",
	"internal/classifier/semantic.go",
	"internal/classifier/streaming.go",
	"internal/extract/decoding.go",
	"internal/extract/extract.go",
	"internal/extract/multipart.go",
	"internal/extract/profile.go",
	"internal/extract/request.go",
	"internal/extract/roles.go",
	"internal/extract/state.go",
	"internal/extract/stream.go",
	"internal/extract/stream_multipart.go",
	"internal/extract/stream_scan.go",
	"internal/rules/loader.go",
	"internal/rules/types.go",
	"rules/contexts.yaml",
	"rules/credentials.yaml",
	"rules/disruption.yaml",
	"rules/embed.go",
	"rules/evasion.yaml",
	"rules/exfiltration.yaml",
	"rules/exploitation.yaml",
	"rules/malware.yaml",
	"rules/manifest.yaml",
	"rules/phishing.yaml",
	"rules/ransomware.yaml",
	"rules/semantics.yaml",
}

func TestClassifierPolicyIdentity(t *testing.T) {
	t.Parallel()
	root := classifierPolicyRepositoryRoot(t)
	files := append([]string(nil), classifierPolicySourceFiles...)
	sort.Strings(files)
	hash := sha256.New()
	seen := make(map[string]struct{}, len(files))
	for _, name := range files {
		name = filepath.ToSlash(filepath.Clean(name))
		if name == "." || strings.HasPrefix(name, "../") || filepath.IsAbs(name) {
			t.Fatalf("classifier policy source path is not repository-relative: %q", name)
		}
		if strings.Contains(name, "evaluation-v10") {
			t.Fatalf("classifier policy identity must not access consumed evaluation data: %q", name)
		}
		if _, duplicate := seen[name]; duplicate {
			t.Fatalf("classifier policy source path is duplicated: %q", name)
		}
		seen[name] = struct{}{}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("read classifier policy source %q: %v", name, err)
		}
		fmt.Fprintf(hash, "%s\x00%d\x00", name, len(data))
		_, _ = hash.Write(data)
		_, _ = hash.Write([]byte{0})
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if actual != ClassifierPolicySHA256 {
		t.Fatalf("classifier policy identity mismatch: got %s want %s", actual, ClassifierPolicySHA256)
	}
	identity := CurrentPolicyIdentity()
	if identity.Version != ClassifierPolicyVersion || identity.SHA256 != ClassifierPolicySHA256 {
		t.Fatalf("compiled classifier policy identity is inconsistent: %+v", identity)
	}
}

func classifierPolicyRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve classifier policy source root")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
