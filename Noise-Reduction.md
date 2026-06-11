# Noise Reduction — Part 1 (Cross-File Deduplication)

**Date:** 2026-06-02  
**Scope:** Deduplicate overlapping guidance between `qe-behaviour.mdc` and `test-plan-generation.mdc`.  
**Principle:** [Karpathy behavioral guidelines](https://github.com/multica-ai/andrej-karpathy-skills/blob/main/.cursor/rules/karpathy-guidelines.mdc) — behavioral rules in one place; workflow rules reference them instead of restating.

---

## Ownership split (after changes)

| Topic | Owner file |
| --- | --- |
| Ask before assuming | `qe-behaviour.mdc` §1 |
| No vague steps / consolidate redundant tests | `qe-behaviour.mdc` §2 |
| Surgical scope / non-goals | `qe-behaviour.mdc` §3 |
| OLM namespace, CR `cluster`, CSV/Subscription patches | `qe-behaviour.mdc` §4 |
| Traceability behavior | `qe-behaviour.mdc` §5 |
| Self-verify behavior | `qe-behaviour.mdc` §6 → points to test-plan Section F |
| Hard stop conditions | `qe-behaviour.mdc` Stop Conditions |
| Test plan workflow (ADR/PR mode, tiers, template, gates) | `test-plan-generation.mdc` |
| Scope boundary triggers (open questions → MQE, customer risk → regression) | `test-plan-generation.mdc` D.2 |
| E2E audit, architecture traps, security logging | `test-plan-generation.mdc` Section G |

---

## Changes applied

### Item 1 — No vague test steps

| File | Change |
| --- | --- |
| `qe-behaviour.mdc` | **Kept** §2 (full rule + BAD/GOOD examples) |
| `test-plan-generation.mdc` | **Removed** duplicate bullets from Quick Start ("specific action", "no vague verbs") |
| `test-plan-generation.mdc` | **Updated** F gate 14 → pointer: `No vague steps (QE Behavioral Guidelines §2)` |

### Item 2 — Traceability

| File | Change |
| --- | --- |
| `qe-behaviour.mdc` | **Kept** §5 as behavioral authority |
| `test-plan-generation.mdc` | **Kept** B.3 (procedural: extract REQ-001, categories) |
| `test-plan-generation.mdc` | **Updated** F gates 11–12 → pointers to §5 |

### Item 3 — Stop conditions

| File | Change |
| --- | --- |
| `qe-behaviour.mdc` | **Added** "Jira only (no ADR, no PR) → STOP" to Stop Conditions |
| `qe-behaviour.mdc` | **Clarified** Jira/ADR conflict → document under "Source conflicts" |
| `test-plan-generation.mdc` | **Replaced** A.2 duplicate bullets with A.2 Hard stops → pointer to QE Stop Conditions |
| `test-plan-generation.mdc` | **Removed** "Jira only \| STOP" row from A.3 mode table |

### Item 4 — Self-verify before output

| File | Change |
| --- | --- |
| `qe-behaviour.mdc` | **Shortened** §6: test plans → run Section F gates; other tasks → checkpoint plan |
| `test-plan-generation.mdc` | **Kept** Section F as authoritative checklist (18 → 17 gates after Item 6) |

### Item 5 — Scope / non-goals

| File | Change |
| --- | --- |
| `qe-behaviour.mdc` | **Kept** §3 Surgical Scope |
| `test-plan-generation.mdc` | **Updated** F gate 17 → pointer to §3 |
| `test-plan-generation.mdc` | **Deleted** H.2 Scope boundary rules (4 duplicate bullets) |
| `test-plan-generation.mdc` | **Restored** scope boundaries in D.2 (with §3 pointer; preserves open-questions→MQE and customer-risk→regression triggers) |
| `test-plan-generation.mdc` | Renumbered former H.3 → H.2 (Upstream SPIRE reference) |

**Why D.2 restoration:** H.2 duplicated §3’s general scope rules, but deleting it also removed two workflow-specific triggers (open questions → MQE, customer risk → regression) that §3 does not state — D.2 keeps those triggers at tier-planning time without re-adding a full H.2 section.

### Item 6 — Redundant tests / budget

| File | Change |
| --- | --- |
| `qe-behaviour.mdc` | **Kept** §2 litmus test |
| `test-plan-generation.mdc` | **Merged** F gates 1 and 18 into gate 1: budget 10–12 + no duplicate observables |
| `test-plan-generation.mdc` | **Removed** former gate 18 (17 gates total) |

### Item 7 — OLM deployment constraints

| File | Change |
| --- | --- |
| `qe-behaviour.mdc` | **Kept** §4 (namespace, CR name, CSV/Subscription DO/DON'T) |
| `test-plan-generation.mdc` | **Removed** CR naming and OLM env bullets from G.6 |
| `test-plan-generation.mdc` | **Added** G.6 pointer: `OLM constraints → QE Behavioral Guidelines §4` |
| `test-plan-generation.mdc` | **Kept** G.6 test-plan-specific traps: fallback ClusterSPIFFEID, Ordered suite, DeferCleanup |

### Quick Start preamble

| File | Change |
| --- | --- |
| `test-plan-generation.mdc` | **Replaced** "Core principles" with **Prerequisites** pointer to `qe-behaviour.mdc` |
| `test-plan-generation.mdc` | **Kept** test-plan-only rules: G.1 audit, G.4 secrets |

---

## Line count impact (approximate)

| File | Before | After | Delta |
| --- | --- | --- | --- |
| `qe-behaviour.mdc` | 122 | 115 | −7 |
| `test-plan-generation.mdc` | 520 | 509 | −11 (Part 2) |
| **Combined always-on** | 642 | 624 | −18 (Part 1 + Part 2) |

### Part 2 — Intra-file trims (2026-06-11)

| File | Change |
| --- | --- |
| `test-plan-generation.mdc` | **Collapsed** B.4 and C.2 audit reminders → pointer to Quick Start + G.1/G.6 |
| `test-plan-generation.mdc` | **Collapsed** G.2 and G.3 catalogs → read `utils.go` / `constants.go` |
| `test-plan-generation.mdc` | **Removed** H.1 methodology table (duplicate of D tier Method column); renumbered SPIRE ref to H.1 |

**Why:** Reference catalogs in rules waste tokens; G.1 and the repo are the source of truth at implementation time.

### Gate checklist in plan file (2026-06-02)

| File | Change |
| --- | --- |
| `test-plan-generation.mdc` | Quick Start: default workflow — revise plan until all F gates Pass, then E2E |
| `test-plan-generation.mdc` | Section E: mandatory deliverable rules + `## Quality Gate Checklist` in template; kept Generation Stats |
| `test-plan-generation.mdc` | Section F: must complete checklist in saved `output/test-plan-*.md` before save |
| `test-plan-generation.mdc` | B.6 / C.5: revise until Pass before E2E |

**Why:** User should paste PR + “create test plan” without extra prompts; compliance is enforced via the saved plan file, not chat-only self-check.

---

## Verification

After editing, confirm:

- [x] Quick Start does not restate vague-step or traceability rules
- [x] A.2 is a single pointer, not duplicate stop bullets
- [x] Section F has 17 gates (gate 1 includes redundancy check)
- [x] G.6 has no CR naming or Subscription patch prose
- [x] Scope boundaries restored in D.2 (open-questions→MQE, customer-risk→regression)
- [x] `qe-behaviour.mdc` Stop Conditions includes Jira-only stop
