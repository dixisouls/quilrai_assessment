# Contributing: the delivery routine

Every change follows the same path. No exceptions for "small" changes.

```
branch ─► small commits (hooks) ─► push (CI) ─► independent review ─► fix ─► PR ─► merge
```

## 1. Branch per unit of work

| Work | Branch |
|---|---|
| Task N | `task/N-<slug>` (e.g. `task/1-mcp-server`) |
| Shared library | `feat/common-<slug>` |
| Tooling / CI | `chore/<slug>` |
| Docker / deploy | `build/<slug>` |
| Fix on main | `fix/<slug>` |

`main` is protected. Direct pushes are blocked on GitHub and refused locally by
the `no-commit-to-branch` hook.

## 2. Small conventional commits

`type(scope): imperative title` (≤ 72 chars), blank line, then a body explaining
what and why. Enforced by `scripts/check_commits.py` in the `commit-msg` hook
and again in CI. AI-tool attribution trailers are rejected.

## 3. Gates

| Check | Local (`make check`) | CI | What it catches |
|---|---|---|---|
| `ruff format` | pre-commit | ✓ | Style drift |
| `ruff check` (incl. bandit `S`, `T20` print-ban, `ASYNC`) | pre-commit | ✓ | Bugs, insecure patterns, stray `print` to stdout |
| `mypy --strict` | pre-push | ✓ | Type errors |
| `pytest` + coverage ≥ 90 % (branch) | pre-push | ✓ | Regressions, untested code |
| Commit policy | commit-msg | ✓ | Non-conventional messages, AI attribution |
| Trojan Source scan | pre-commit | ✓ | Invisible bidi / zero-width characters |
| `uv lock --check` | `make security` | ✓ | Lockfile out of sync with `pyproject.toml` |
| `pip-audit` (hashed lockfile export) | `make security` | ✓ | Known CVEs in **all** locked deps, dev included |
| gitleaks (full history) | if installed | ✓ | Committed secrets |
| actionlint | if installed | ✓ | Broken or insecure workflow YAML |
| CodeQL `security-extended` (Python + Actions) | — | ✓ | SAST: injection, path traversal, workflow script injection |
| Dependency review | — | PR only | New deps with CVEs or copyleft licences |
| Dependabot | — | weekly | Stale action SHAs and dependencies |
| `detect-private-key`, large files, merge markers | pre-commit | — | Accidental commits |

Planned with the Docker step: `hadolint` (Dockerfile lint), `trivy` (image CVEs
and misconfig), image build, and an SBOM.

CI hardening: actions pinned to commit SHAs, a read-only default
`GITHUB_TOKEN`, `persist-credentials: false`, downloaded binaries verified by
SHA-256, and event data passed via `env:` instead of being inlined into scripts.

## 4. Independent review before merge

Before opening the PR, a **fresh reviewer agent with no shared context** reviews
the branch diff against `ASSESSMENT.md` and `CLAUDE.md`. The author doesn't get
to grade their own work. Findings are fixed in follow-up commits (or rebutted
with reasoning in the PR) and logged in `MISTAKES.md` where they reveal a
mistake.

## 5. Merge

A PR into `main` needs every required check green and all conversations
resolved. Merge with a **merge commit** (no squash) so the small commits survive
and each task stays visible as one merge.
