//go:build consumed_evaluation
// +build consumed_evaluation

package classifier

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var evaluationHistoricalImplementationPatterns = []string{
	"go.mod",
	"go.sum",
	"internal/classifier/*.go",
	"internal/extract/*.go",
	"internal/rules/*.go",
	"rules/*.go",
}

type evaluationHistoricalBlob struct {
	Path   string
	SHA256 string
}

func evaluationRequireHistoricalGitSnapshot(
	t *testing.T,
	root, commit, tree, implementationWant, rulesWant, embeddedWant string,
	evidence []evaluationHistoricalBlob,
) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		if os.IsNotExist(err) {
			t.Fatal("historical Git snapshot recomputation requires a full Git checkout")
		}
		t.Fatalf("inspect Git metadata: %v", err)
	}
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatalf("historical Git snapshot requires git: %v", err)
	}
	actualTree, err := evaluationGitText(git, root, "rev-parse", commit+"^{tree}")
	if err != nil {
		shallow, shallowErr := evaluationGitText(git, root, "rev-parse", "--is-shallow-repository")
		if shallowErr == nil && shallow == "true" {
			t.Fatalf(
				"historical Git snapshot commit %s is unavailable in a shallow checkout; fetch full history: %v",
				commit,
				err,
			)
		}
		t.Fatal(err)
	}
	if actualTree != tree {
		t.Fatalf("historical snapshot tree mismatch: got %s want %s", actualTree, tree)
	}
	for _, item := range evidence {
		if item.Path == "" || len(item.SHA256) != sha256.Size*2 {
			t.Fatalf("invalid historical evidence binding: path=%q sha256=%q", item.Path, item.SHA256)
		}
		data, err := evaluationGitBlob(git, root, commit, item.Path)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		actual := hex.EncodeToString(digest[:])
		if actual != item.SHA256 {
			t.Fatalf("historical evidence blob mismatch for %s: got %s want %s", item.Path, actual, item.SHA256)
		}
	}

	names, err := evaluationGitTreeNames(git, root, commit)
	if err != nil {
		t.Fatal(err)
	}
	implementation, err := evaluationGitSnapshotHash(git, root, commit, names, evaluationHistoricalImplementationPatterns, true)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := evaluationGitSnapshotHash(git, root, commit, names, []string{"rules/*.yaml"}, false)
	if err != nil {
		t.Fatal(err)
	}
	embedded, err := evaluationGitEmbeddedRulesHash(git, root, commit, names)
	if err != nil {
		t.Fatal(err)
	}
	if implementation != implementationWant || rules != rulesWant || embedded != embeddedWant {
		t.Fatalf(
			"historical Git snapshot mismatch: implementation=%s rules=%s embedded=%s",
			implementation,
			rules,
			embedded,
		)
	}
}

func evaluationGitText(git, root string, args ...string) (string, error) {
	commandArgs := append([]string{"-C", root}, args...)
	output, err := exec.Command(git, commandArgs...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func evaluationGitTreeNames(git, root, commit string) ([]string, error) {
	command := exec.Command(git, "-C", root, "ls-tree", "-r", "-z", "--name-only", commit, "--")
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-tree %s: %w", commit, err)
	}
	raw := strings.Split(string(output), "\x00")
	names := make([]string, 0, len(raw))
	for _, name := range raw {
		if name != "" {
			names = append(names, name)
		}
	}
	return names, nil
}

func evaluationGitSnapshotHash(
	git, root, commit string,
	names, patterns []string,
	excludeTests bool,
) (string, error) {
	paths, err := evaluationGitMatchPaths(names, patterns, excludeTests)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	for _, name := range paths {
		data, err := evaluationGitBlob(git, root, commit, name)
		if err != nil {
			return "", err
		}
		_, _ = io.WriteString(hash, name)
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write(data)
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func evaluationGitEmbeddedRulesHash(git, root, commit string, names []string) (string, error) {
	paths, err := evaluationGitMatchPaths(names, []string{"rules/*.yaml"}, false)
	if err != nil {
		return "", err
	}
	outer := sha256.New()
	for _, name := range paths {
		data, err := evaluationGitBlob(git, root, commit, name)
		if err != nil {
			return "", err
		}
		inner := sha256.Sum256(data)
		_, _ = fmt.Fprintf(outer, "%s  %s\n", hex.EncodeToString(inner[:]), name)
	}
	return hex.EncodeToString(outer.Sum(nil)), nil
}

func evaluationGitMatchPaths(names, patterns []string, excludeTests bool) ([]string, error) {
	paths := make([]string, 0, 32)
	for _, pattern := range patterns {
		included := 0
		for _, name := range names {
			matched, err := pathpkg.Match(pattern, name)
			if err != nil {
				return nil, fmt.Errorf("historical snapshot pattern %q: %w", pattern, err)
			}
			if !matched || (excludeTests && strings.HasSuffix(name, "_test.go")) {
				continue
			}
			paths = append(paths, name)
			included++
		}
		if included == 0 {
			return nil, fmt.Errorf("historical snapshot pattern %q matched no eligible files", pattern)
		}
	}
	sort.Strings(paths)
	return paths, nil
}

func evaluationGitBlob(git, root, commit, name string) ([]byte, error) {
	command := exec.Command(git, "-C", root, "cat-file", "blob", commit+":"+name)
	data, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("git cat-file %s:%s: %w", commit, name, err)
	}
	return data, nil
}
