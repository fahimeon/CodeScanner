# Candidate-Discovery Plan (Phase 2–3)

How the study discovers, records, and deduplicates candidate repositories —
both the **treated** (Claude Code-attributed) pool and the **control**
(non-attributed) pool. This is a plan, not yet an execution; no queries have
been run.

---

## 1. Goals and constraints

- Build a candidate pool large enough that, after every eligibility filter
  (especially the deployment gate), the **deployed** track can reach up to 500
  and the **repository-only** track and **control** cohort are well populated.
- Treat the pool size as an **output of a measured funnel**, not a fixed guess.
- Respect GitHub API limits and terms; never scrape HTML search pages.
- Save every raw result immutably; make the whole process resumable.

---

## 2. What we search for

Stable attribution anchors (never a model name — the label varies):

| Signal | Confidence | Query string |
|---|---|---|
| `Co-Authored-By: Claude … <noreply@anthropic.com>` | High | `"noreply@anthropic.com"` |
| `Generated with Claude Code` | High | `"Generated with Claude Code"` |
| `Claude-Session:` | Supporting | `"Claude-Session:"` |

The `Co-Authored-By` and `Generated with Claude Code` lines live in the commit
**message body**, which the commit-search index covers. `Claude-Session:` is
supporting-only and never sufficient alone.

> **Probe first.** Before the full run, a one-off probe confirms that GitHub
> actually free-text-matches the co-author trailer as expected (email tokens can
> behave oddly). If `"noreply@anthropic.com"` under-matches, fall back to
> phrase-anchored queries (`"Co-Authored-By: Claude"`) and record the decision.

---

## 3. API realities (corrections to the naive plan)

- **Rate limit:** commit search is **~30 requests/minute** (the search-specific
  limit), *not* the 5,000/hour REST core limit. The collector paces to ≤ 30
  search req/min with jittered spacing.
- **Result cap:** each query returns at most **1,000** results. A query that
  saturates (≈ ≥ 950) is silently truncated and biased toward whatever GitHub
  ranks first, so saturating queries must be split finer.
- **Index scope & mutability:** commit search covers indexed commits and can
  change over time; deleted/renamed repos vanish. The saved raw JSON is the
  reproducibility artifact.
- **Auth required:** unauthenticated search is far more limited. `gh auth status`
  must pass before collection (checked by `make check`).

---

## 4. Time-slicing with adaptive sub-slicing

Search the window **2025-02-24 → 2026-06-30** in slices, per signal:

1. Start with **monthly** slices (`author-date:YYYY-MM-DD..YYYY-MM-DD`); the
   first slice starts 2025-02-24.
2. If a slice returns **≥ 950** results (`saturation_threshold`), it is truncated
   — **recurse**: split that slice into halves (→ bi-weekly → weekly → daily)
   until every leaf slice is below the threshold.
3. Record the slice tree so the partition is auditable and reproducible.

This removes the recency/ranking bias a single 1,000-cap query would introduce.

`gh` invocation per leaf slice:

```bash
gh search commits '"noreply@anthropic.com"' \
  --author-date '2025-03-01..2025-03-15' \
  --limit 1000 \
  --json sha,repository,commit,parents,author,committer,url \
  > data/raw/github-search/anthropic-email-2025-03-01_2025-03-15.json
```

Filenames encode signal + slice: `{signal}-{start}_{end}.json`. Files under
`data/raw/github-search/` are **never overwritten** (resume-safe).

---

## 5. Reliability engineering

The collector (`scripts/collect_candidates.py`) implements:

- **Sequential processing** (no uncontrolled concurrency).
- **Caching:** if a slice's output file already exists and validates as JSON,
  skip it (resumption).
- **Exponential backoff with jitter** on `403`/`429`/secondary-rate-limit and
  transient network errors (via `tenacity`); respect `Retry-After`.
- **Rate-limit awareness:** proactively pace to the search limit; on repeated
  429s, back off hard rather than hammering (GitHub restricts integrations that
  ignore limits).
- **Per-request log** (`logs/collect_candidates.jsonl`) recording: query, date
  range, execution timestamp, result count, HTTP status, retry count, error
  message, output filename.
- **Atomic writes** (`*.tmp` → `os.replace`) and **JSON validation** before a
  file is accepted.
- **Safe resumption** after interruption (idempotent by slice).

---

## 6. Merge & deduplicate (Phase 3)

Unit of analysis is the **repository**, not the commit.

1. Load all raw slice files (treated) and control files separately.
2. Deduplicate first by **commit SHA**, then group by **`owner/repo`**.
3. Emit one candidate record per repository preserving:
   `repository_full_name`, `repository_url`, `matching_commit_sha`,
   `matching_commit_url`, `matching_commit_date`, `matching_attribution`
   (which signal(s)), `matching_commit_message` (trimmed, no secrets),
   `number_of_claude_attributed_commits` (from search, refined later in Phase 6),
   `first_claude_commit_date`, `last_claude_commit_date`.

Outputs:
```
data/interim/claude-candidate-repositories.csv
data/interim/claude-candidate-repositories.json
```

Note: search-time attributed-commit counts are a **lower bound** (search is
capped/indexed); Phase 6 recomputes exact counts from cloned git history.

---

## 7. Control cohort discovery (non-Claude)

The control pool must be discovered **without any attribution signal** and must
pass the **same** web-app / language / not-fork / not-archived / LOC / deployment
filters, so the only systematic difference is detectable Claude attribution.

Approach (`collect_candidates.py --control`, output →
`data/raw/github-search-control/`):

- Use GitHub **repository** search (not commit search) constrained to
  `language:TypeScript` / `language:JavaScript`, `fork:false`, `archived:false`,
  `pushed:2025-02-24..2026-06-30`, sliced by creation/push date and by star
  buckets to avoid the 1,000-cap and popularity skew.
- **Exclude** any repo that shows **any** attribution signal (checked in Phase 6
  against git history: a control repo with a `noreply@anthropic.com` trailer is
  removed from the control pool).
- Oversample, because matching (Phase 18, 1:1 on size stratum + framework +
  provider + age) will not find a partner for every treated unit; the achieved
  match rate is reported.

Matching itself happens at selection time, not discovery time; discovery only
needs a large, filter-eligible non-Claude pool.

---

## 8. Funnel-based pool sizing

Rather than committing to a fixed pool, run a **first batch** (~1,000 treated
candidates), push it through the full eligibility funnel, and measure the pass
rate at each stage:

```
candidates
  → not fork/archived/empty
    → JS/TS + package.json
      → web-app detected
        → 500–100k relevant LOC
          → substantial attribution (rules A–D) + reachable commit
            → not excluded (vuln-lab/docs/library/tutorial/duplicate)
              → [deployment gate] discoverable URL
                → live + repo-matched (Level A/B/C)   ← dominant attrition here
```

The deployment gate is expected to be the dominant filter. From the measured
per-stage pass rates, back-calculate the pool size needed to land the targets
(config hint: escalate toward 10,000–30,000 candidates if the deployment
pass-rate is low). Every stage's counts feed a CONSORT-style funnel table and
figure. **If the eligible deployed pool is < 500, report the number and the
per-stage reasons — never weaken criteria to reach 500.**

---

## 9. Outputs of Phase 2–3

| Path | Contents |
|---|---|
| `data/raw/github-search/*.json` | Immutable treated search dumps (per signal × slice) |
| `data/raw/github-search-control/*.json` | Immutable control search dumps |
| `logs/collect_candidates.jsonl` | Per-request audit log |
| `data/interim/claude-candidate-repositories.{csv,json}` | Deduplicated treated candidates |
| `data/interim/control/control-candidate-repositories.{csv,json}` | Deduplicated control candidates |
| `data/interim/search-slice-tree.json` | Auditable record of the adaptive slice partition |

Nothing in this phase clones repositories, contacts any deployment, or runs a
scanner. Those begin only after the population is frozen and the sample selected.
