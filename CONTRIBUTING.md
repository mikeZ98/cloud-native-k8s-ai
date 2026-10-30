# Contributing to cloud-native-k8s-ai

## ⛔ Sole-Contributor Invariant (non-negotiable)

Every commit in this repository, on every branch, MUST have **author and committer** set to exactly:

| Field | Value |
|-------|-------|
| Name  | `mikeZ98` |
| Email | `145975972+mikeZ98@users.noreply.github.com` |

- No other name, no machine username, no personal or local email: zero tolerance.
- Commit messages MUST NOT contain AI attribution or co-author metadata. Banned: `Co-Authored-By`,
  `Generated-by`, `Generated with`, `Assisted-by`, `AI-generated`, the 🤖 emoji, and any mention of
  Claude, Anthropic, ChatGPT, OpenAI, GPT-n, Copilot, Gemini or Cursor. The literal file name
  `CLAUDE.md` is the only exception.
- Every GitHub web-UI merge method (merge, squash and rebase) and `gh pr merge` record
  `GitHub <noreply@github.com>` as committer and **will fail** the audit. Fast-forward `main`
  locally instead (see below).

### How it is enforced

| Layer | Where | Checks |
|-------|-------|--------|
| `pre-commit` | `.githooks/pre-commit` | author/committer identity; blocks `.cache/`, venvs, `.env*`, keys, Terraform state/vars, kubeconfigs; ruff on staged Python; yamllint on staged YAML |
| `commit-msg` | `.githooks/commit-msg` | forbidden trailers/terms; Conventional Commit subject; identity re-check (covers `--author` and `--amend`) |
| `pre-push` | `.githooks/pre-push` | full audit of every commit being pushed |
| Manual / CI | `scripts/audit-attribution.sh` | configured identity plus a full audit of the branch history (`--history-only` in CI) |

The policy (allowed identity, banned message patterns and forbidden paths) lives in one place:
`.githooks/_policy.sh`. Audit any range by hand with `scripts/audit-attribution.sh [<rev-list args>]`
(default: `HEAD`). Never bypass hooks with `--no-verify`.

## Host isolation (hermetic validation)

The test suite never touches the network, a live Kubernetes cluster or a cloud API. pytest runs
with `--disable-socket` (only AF_UNIX is allowed, for the asyncio self-pipe). Manifests, Helm
templates and Terraform are validated statically and offline. `.envrc` points `KUBECONFIG` at an
empty project-local file so `kubectl`/`helm` run from this repo cannot reach a real cluster.

## Environment setup (macOS, external SSD)

All caches, the virtualenv, temp files, kube/helm/terraform homes and the Colima VM live under
`./.cache/` on `/Volumes/KINGSTONE_SSD`. Nothing is written to the internal disk.

```bash
brew install uv direnv
direnv allow          # pins caches, isolates KUBECONFIG, sets core.hooksPath + the git identity
uv sync               # downloads CPython 3.12 and creates .cache/venv
```

## Quality gates

```bash
ruff check . && ruff format --check .
mypy                      # strict, configured in pyproject.toml
bandit -c pyproject.toml -r src
yamllint --strict .
pytest                    # hermetic: sockets disabled, coverage ≥ 90% (branch)
scripts/audit-attribution.sh
```

## Pull request workflow (fast-forward only)

```bash
git switch main && git pull --ff-only
git switch -c feat/my-change                 # one topic per branch
git commit                                   # hooks check identity, message, paths, lint
git push -u origin feat/my-change            # pre-push audits every new commit
gh pr create --fill --base main
git switch main
git merge --ff-only feat/my-change           # your commits, unchanged
git push origin main                         # GitHub marks the PR as merged
git push origin --delete feat/my-change && git branch -d feat/my-change
```

If `main` moved meanwhile, `--ff-only` refuses: rebase the branch onto `main`, push it with
`--force-with-lease`, then fast-forward.

## Commit discipline

- [Conventional Commits](https://www.conventionalcommits.org/): `<type>(<scope>): <summary>`, subject
  ≤ 100 characters. Types: `feat fix chore docs test build ci refactor perf style revert`.
- One logical change per commit. Keep commits atomic and green.
- Dependency updates: `uv lock --upgrade-package <name>`, run the gates, commit `uv.lock`. Bot-authored
  update commits (e.g. Dependabot) fail the audit by design.
