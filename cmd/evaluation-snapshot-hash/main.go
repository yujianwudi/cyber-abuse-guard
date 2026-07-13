package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	implementation, err := snapshot([]string{
		"go.mod", "go.sum", "internal/classifier/*.go", "internal/extract/*.go",
		"internal/rules/*.go", "rules/*.go",
	}, true)
	if err != nil {
		fail(err)
	}
	rules, err := snapshot([]string{"rules/*.yaml"}, false)
	if err != nil {
		fail(err)
	}
	embedded, err := embeddedRulesHash()
	if err != nil {
		fail(err)
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{
		"implementation_dependency": implementation,
		"yaml_rules":                rules,
		"embedded_ruleset":          embedded,
	})
}

func snapshot(patterns []string, excludeTests bool) (string, error) {
	paths := make([]string, 0, 32)
	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.FromSlash(pattern))
		if err != nil {
			return "", err
		}
		for _, path := range matches {
			if excludeTests && strings.HasSuffix(path, "_test.go") {
				continue
			}
			paths = append(paths, path)
		}
	}
	if len(paths) == 0 {
		return "", fmt.Errorf("empty snapshot")
	}
	sort.Strings(paths)
	hash := sha256.New()
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		_, _ = io.WriteString(hash, filepath.ToSlash(path))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write(data)
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func embeddedRulesHash() (string, error) {
	paths, err := filepath.Glob("rules/*.yaml")
	if err != nil || len(paths) == 0 {
		return "", fmt.Errorf("embedded rules: %w", err)
	}
	sort.Strings(paths)
	outer := sha256.New()
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		inner := sha256.Sum256(data)
		_, _ = fmt.Fprintf(outer, "%s  %s\n", hex.EncodeToString(inner[:]), filepath.ToSlash(path))
	}
	return hex.EncodeToString(outer.Sum(nil)), nil
}
