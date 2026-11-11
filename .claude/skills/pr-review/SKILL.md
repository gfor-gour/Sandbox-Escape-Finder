---
name: pr-review
description: Review a GitHub PR for this project. Reads the project docs first, runs /code-review plus a Codex cross-check, fixes only critical issues, and pushes to the PR branch.
---

# PR review (SandboxEscapeFinder)

Usage: `/pr-review <PR URL or number>`

1. **Learn the codebase first.** Read `README.md`, `RESEARCH_SUMMARY.md`, and `docs/*.md` before looking at the diff. The project measures which RestrictedPython 8.5 defense layer stops each of 20 payloads (static analyzer + subprocess prober + canary oracle). Every number in docs must be reproducible from `scripts/reproduce.py`.
2. **Review with `/code-review`** at `medium` effort on the PR (cheapest level that still finds real bugs). Use `gh pr view/diff` for context.
3. **Cross-check with Codex** in the loop: run `codex review --base <base-branch>` from the PR branch checkout. Merge its findings with step 2's; discard anything neither the code nor a test confirms.
4. **Fix critical issues only** (wrong results, broken tests, safety-scope violations such as payloads escaping the temp dir/timeout, claims in docs that the code contradicts). Report non-critical findings without changing them.
5. **Verify** with `python -m pytest -q`, then commit and push to the PR's head branch. Never force-push.
6. Report: findings (fixed vs. left), test result, commit hash.
