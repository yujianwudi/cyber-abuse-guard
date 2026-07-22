#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
cd "$root"

safe_roots=(
  cmd/cyber-abuse-guard
  cmd/development-adversarial-v11-prep-validator
  cmd/development-public-jailbreak-patterns-v1-validator
  internal/audit
  internal/buildinfo
  internal/classifier
  internal/config
  internal/extract
  internal/explanation
  internal/fixturepublish
  internal/plugin
  internal/round8test
  internal/rules
  internal/subject
  integration/cpalatestcontract
  integration/pluginstorecontract
  rules
)

while IFS= read -r -d '' file; do
  case "$file" in
    *.go) ;;
    *) continue ;;
  esac
  case "${file,,}" in
    internal/classifier/*evaluation*|internal/classifier/*holdout*|internal/classifier/*consumed*|internal/classifier/*private*|internal/classifier/*retired*|internal/classifier/*blind*)
      continue
      ;;
  esac
  printf '%s\0' "$file"
done < <(git ls-files -co --exclude-standard -z -- "${safe_roots[@]}")
