# VulnOS — AI Engineering Label Taxonomy & Lifecycle States
## GitHub Label Conventions for Autonomous Engineering Management

**Document Version:** 1.0.0  
**Effective Date:** 2026-11-02  
**Target Path:** `.orchestrator/LABELS.md`  

---

## 1. Task Lifecycle Labels

These labels track the state of an issue or PR through the development lifecycle:

| Label | Color | Description | Assigned By | Next Transition |
|---|---|---|---|---|
| `status:draft` | `#cfd3d7` | Issue is being drafted; not ready for execution. | AI Manager / Human | `status:ready` |
| `status:ready` | `#0e8a16` | Issue specification is complete, scoped, and ready for an agent to claim. | AI Manager / Human | `status:in-progress` |
| `status:in-progress` | `#1d76db` | Agent has claimed the task and is developing on a feature branch. | Agent (Antigravity) | `status:review-needed` |
| `status:review-needed` | `#fbca04` | PR is open, all quality gates pass, and PR awaits review. | Agent (Antigravity) | `status:changes-requested` or `status:approved` |
| `status:changes-requested` | `#d93f0b` | Reviewer requested corrections; agent must address feedback. | AI Manager / Reviewer | `status:in-progress` $\rightarrow$ `status:review-needed` |
| `status:approved` | `#006b75` | PR meets all review criteria and is approved for merge. | AI Manager / Reviewer | Merged $\rightarrow$ Closed |
| `status:blocked` | `#b60205` | Task is blocked by an upstream dependency, missing spec, or technical blocker. | Any | `status:ready` once unblocked |

---

## 2. Agent Assignment Labels

| Label | Color | Description |
|---|---|---|
| `agent:antigravity` | `#5319e7` | Task assigned to Antigravity coding assistant. |
| `agent:human` | `#0052cc` | Task reserved for human engineer or manual intervention. |

---

## 3. Priority Labels

| Label | Color | Description |
|---|---|---|
| `priority:critical` | `#b60205` | Critical security flaw, blocker, or default branch failure. Immediate priority. |
| `priority:high` | `#d93f0b` | Key roadmap deliverable or prerequisite for subsequent phases. |
| `priority:medium` | `#fbca04` | Standard roadmap feature or scheduled refactoring. |
| `priority:low` | `#c2e0c6` | Non-blocking enhancement, documentation polish, or minor cleanup. |

---

## 4. Phase & Type Labels

### Phase Labels
- `phase:p1-blueprint`
- `phase:p2-platform`
- `phase:p3-recon`
- `phase:p4-scanner`
- `phase:p5-agent`
- `phase:p6-reporting`
- `phase:p7-ops`

### Type Labels
- `type:feature` (new capability or endpoint)
- `type:bugfix` (defect resolution)
- `type:security` (security vulnerability, scope protection, RLS)
- `type:test` (unit, integration, or adversarial test additions)
- `type:docs` (documentation updates)
- `type:refactor` (code structure improvement without behavior change)
