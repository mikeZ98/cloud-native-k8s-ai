# shellcheck shell=bash
# Shared attribution policy for git hooks and scripts/audit-attribution.sh.
# Sourced, never executed. Git ignores this file as a hook (not a hook name).

readonly POLICY_ALLOWED_NAME="mikeZ98"
readonly POLICY_ALLOWED_EMAIL="145975972+mikeZ98@users.noreply.github.com"

# Case-insensitive ERE matched against commit messages (after stripping
# comments and the literal file name CLAUDE.md, which docs commits may cite).
readonly POLICY_FORBIDDEN_MSG_RE='co-authored-by|generated-by|generated[ -]with|ai-generated|assisted-by|signed-off-by:.*(noreply@anthropic|openai)|claude|anthropic|chatgpt|openai|gpt-[0-9]|copilot|gemini|cursor\.(sh|com)|🤖'

readonly POLICY_CONVENTIONAL_RE='^(feat|fix|chore|docs|test|build|ci|refactor|perf|style|revert)(\([a-z0-9._/-]+\))?!?: [^ ].{0,98}$'

# ERE for staged paths that must never be committed: caches, virtualenvs,
# secrets, Terraform state/vars/working dirs and kubeconfigs.
readonly POLICY_FORBIDDEN_PATH_RE='(^|/)(\.cache|\.venv|__pycache__|\.mypy_cache|\.ruff_cache|\.pytest_cache|\.terraform)/|(^|/)\.env(\..+)?$|(^|/)\.envrc\.local$|\.(pem|key|p12|pfx)$|\.tfstate(\..+)?$|\.tfvars(\.json)?$|(^|/)kubeconfig[^/]*$|\.kubeconfig$'
# Exceptions to POLICY_FORBIDDEN_PATH_RE (templates without real values).
readonly POLICY_ALLOWED_PATH_RE='(^|/)\.env\.example$'

policy_err() { printf '\033[31m✖ %s\033[0m\n' "$*" >&2; }
policy_ok() { printf '\033[32m✔ %s\033[0m\n' "$*" >&2; }

# policy_check_identity <role> <name> <email>
policy_check_identity() {
  local role="$1" name="$2" email="$3"
  if [[ "$name" != "$POLICY_ALLOWED_NAME" || "$email" != "$POLICY_ALLOWED_EMAIL" ]]; then
    policy_err "$role identity '$name <$email>' violates the sole-contributor invariant."
    policy_err "Expected: '$POLICY_ALLOWED_NAME <$POLICY_ALLOWED_EMAIL>'."
    return 1
  fi
}

# policy_parse_ident <git-var-ident>  →  prints "name<TAB>email"
policy_parse_ident() {
  sed -E 's/^(.*) <([^>]*)> [0-9]+ [-+][0-9]{4}$/\1\t\2/' <<<"$1"
}

# policy_clean_message — strip comments and anything below the scissors line.
policy_clean_message() {
  sed -e '/^# ------------------------ >8 ------------------------$/,$d' -e '/^#/d'
}

# policy_check_message <message-text>
policy_check_message() {
  local msg="$1" hits
  hits="$(sed -E 's/CLAUDE\.md//g' <<<"$msg" | grep -inE "$POLICY_FORBIDDEN_MSG_RE" || true)"
  if [[ -n "$hits" ]]; then
    policy_err "Commit message contains forbidden AI attribution / co-author metadata:"
    printf '    %s\n' "$hits" >&2
    return 1
  fi
}

# policy_check_subject <first-line>
policy_check_subject() {
  local subject="$1"
  case "$subject" in
    Merge\ *|fixup!\ *|squash!\ *|amend!\ *) return 0 ;;
  esac
  if ! grep -qE "$POLICY_CONVENTIONAL_RE" <<<"$subject"; then
    policy_err "Subject is not a Conventional Commit (max 100 chars): '$subject'"
    policy_err "Format: <type>(<scope>)?: <summary>   types: feat fix chore docs test build ci refactor perf style revert"
    return 1
  fi
}

# policy_forbidden_paths  (stdin: one path per line)  →  prints offending paths
policy_forbidden_paths() {
  grep -E "$POLICY_FORBIDDEN_PATH_RE" | grep -vE "$POLICY_ALLOWED_PATH_RE" || true
}
