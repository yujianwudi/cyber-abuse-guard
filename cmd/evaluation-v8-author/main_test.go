package main

import (
	"errors"
	"testing"

	"github.com/yujianwudi/cyber-abuse-guard/internal/extract"
)

func TestHealthyExtractionRejectsParseError(t *testing.T) {
	t.Parallel()
	result := extract.Result{Parts: []string{"non-empty"}, ParseError: "invalid nested JSON"}
	if healthyExtraction(result, nil) {
		t.Fatal("parse errors must fail extraction validation")
	}
}

func TestHealthyExtractionRequiresAllGates(t *testing.T) {
	t.Parallel()
	if !healthyExtraction(extract.Result{Parts: []string{"ok"}}, nil) {
		t.Fatal("healthy extraction was rejected")
	}
	if healthyExtraction(extract.Result{Parts: []string{"ok"}}, errors.New("extract failed")) {
		t.Fatal("extract errors must fail validation")
	}
	if healthyExtraction(extract.Result{Parts: []string{"ok"}, Truncated: true}, nil) {
		t.Fatal("truncated extraction must fail validation")
	}
	if healthyExtraction(extract.Result{}, nil) {
		t.Fatal("empty extraction must fail validation")
	}
}
