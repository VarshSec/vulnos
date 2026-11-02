# VulnOS — AI Engineering Execution Policy
## Operational Rules, Branching Standards, Scope Confinement & Quality Gates

**Document Version:** 1.0.0  
**Effective Date:** 2026-11-02  
**Target Path:** `.orchestrator/EXECUTION_POLICY.md`  

---

## 1. Core Operating Principles for AI Agents

All autonomous agents (including Antigravity) developing on VulnOS operate under strict safety, quality, and confinement boundaries.

### Non-Negotiable Directives:
1. **Never Modify the Default Branch Directly:** All changes MUST be developed on an isolated feature or bugfix branch and merged via Pull Request after review and CI verification.
2. **Strict Scope Confinement:** An agent assigned a specific issue MUST touch only the files explicitly required by that issue's specification. Unrelated refactoring, dependency updates, or speculative code additions are strictly forbidden.
3. **No Weakened Assertions or Bypassed Tests:** If a test fails, the agent must fix the underlying implementation defect. Weakening assertions, removing tests, adding arbitrary `type: ignore` comments, or skipping tests with `@pytest.mark.skip` to pass CI is a critical violation.
4. **Zero Secret Leakage:** Never commit `.env` files, actual credentials, private keys, API keys, or production tokens.
5. **No Scope Escapes:** Never execute network operations, port scans, or HTTP requests against external systems without verified, written legal authorization.
6. **No Speculative Subdivisions:** Do not break a cohesive task into sub-sub-submilestones or author redundant audit documents unless explicitly requested.

---

## 2. Git Branching & Commit Conventions

### 2.1 Branch Naming Format
Branches must follow the standardized structure:

$$\mathbf{<type>}/\mathbf{issue-}<\text{id}>-\mathbf{<short-description>}$$

- Feature additions: `feat/issue-42-subfinder-adapter`
- Bug fixes: `fix/issue-89-scope-cidr-normalization`
- Security patches: `security/issue-104-redact-token-leak`
- Refactoring: `refactor/issue-55-consolidate-docs`
- Documentation: `docs/issue-12-architecture-update`

### 2.2 Commit Message Standards
All commits must follow the **Conventional Commits** specification:

```text
<type>(<scope>): <concise imperative summary>

[Optional detailed body explaining rationale, non-obvious choices, and security context]

Closes #<issue_number>
```

Permitted types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `security`.

---

## 3. Mandatory Pre-Submission Quality Gates

Before opening a Pull Request, the agent MUST run and verify all 5 quality gates locally. Every check must exit with code 0:

```bash
# 1. Linting & code standards
uv run ruff check .

# 2. Code formatting
uv run ruff format --check .

# 3. Static type analysis
uv run mypy backend tests

# 4. Database schema verification
uv run alembic heads

# 5. Full test suite execution
uv run pytest -v
```

If any gate fails, the agent MUST correct the code before proceeding.

---

## 4. Evidence Packaging Requirement

When submitting a Pull Request, the agent must provide concrete execution evidence:
- **Test execution summary:** Exact output showing total passed tests (e.g. `477 passed in 9.79s`).
- **Linter & Type check output:** Evidence of 0 errors.
- **Modified files list:** Complete list of files created or modified.
- **Security verification notes:** Explicit statement confirming that tenant isolation, scope rules, and row-locking invariants were preserved.
