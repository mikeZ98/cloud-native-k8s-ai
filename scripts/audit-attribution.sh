#!/usr/bin/env bash
# Audit commits for the sole-contributor + no-AI-attribution invariant.
#
# Usage: scripts/audit-attribution.sh [--history-only] [<git rev-list args>...]   (default: HEAD)
# Used by .githooks/pre-push locally and by CI. Also verifies the local git
# identity so the next commit cannot violate the invariant either.
# --history-only skips that identity check: CI audits commits but never creates
# any, and a runner's auto-detected identity says nothing about the history.
set -euo pipefail

check_identity=1
if [[ "${1:-}" == "--history-only" ]]; then
  check_identity=0
  shift
fi

ROOT="$(git rev-parse --show-toplevel)"
# shellcheck source=../.githooks/_policy.sh
source "$ROOT/.githooks/_policy.sh"

fail=0

# The identity git would stamp on the next commit (honours GIT_* env overrides).
if ((check_identity)); then
  IFS=$'\t' read -r a_name a_email <<<"$(policy_parse_ident "$(git var GIT_AUTHOR_IDENT)")"
  IFS=$'\t' read -r c_name c_email <<<"$(policy_parse_ident "$(git var GIT_COMMITTER_IDENT)")"
  policy_check_identity "Configured author" "$a_name" "$a_email" || fail=1
  policy_check_identity "Configured committer" "$c_name" "$c_email" || fail=1
fi

if (($# == 0)); then
  if ! git rev-parse --verify --quiet HEAD >/dev/null; then
    ((fail)) && { policy_err "Attribution audit FAILED (no commits yet)."; exit 1; }
    policy_ok "Attribution audit passed (no commits yet; identity verified)."
    exit 0
  fi
  set -- HEAD
fi

count=0
while IFS= read -r sha; do
  count=$((count + 1))
  IFS=$'\x1f' read -r an ae cn ce <<<"$(git log -1 --format='%an%x1f%ae%x1f%cn%x1f%ce' "$sha")"
  short="${sha:0:12}"
  policy_check_identity "[$short] Author" "$an" "$ae" || fail=1
  policy_check_identity "[$short] Committer" "$cn" "$ce" || fail=1
  policy_check_message "$(git log -1 --format=%B "$sha")" || { policy_err "  ↳ in commit $short"; fail=1; }
done < <(git rev-list "$@")

if ((fail)); then
  policy_err "Attribution audit FAILED ($count commit(s) scanned)."
  exit 1
fi
policy_ok "Attribution audit passed ($count commit(s) scanned)."
