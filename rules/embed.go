// Package ruledata owns the versioned default YAML assets embedded in the
// plugin. Parsing and validation live in internal/rules.
package ruledata

import "embed"

// FS contains only the checked-in default YAML rule documents.
//
//go:embed *.yaml
var FS embed.FS
