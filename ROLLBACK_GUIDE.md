# Newton Security Lab — Reversibility & Rollback Guide

Every experiment in this local simulation is protected by **two independent recovery layers**:
1. **`lab_rollback.py`** — Immutable baseline backup, before/after snapshots, SHA-256 verification, and one-command Emergency Reset.
2. **Local Git Safety Branch** — Clean `main` baseline commit + dedicated `experiment/security-lab` branch (strictly local, no remotes).

---

## 1. Emergency Reset (One-Command Full Recovery)

To immediately restore the entire local simulation to its exact original clean baseline, remove any extra experimental files, verify all SHA-256 checksums, and run the automated test suite:

```bash
python3 lab_rollback.py reset
```

Expected exit code: `0`, confirming both **SHA-256 baseline match** and **all automated tests passing**.

---

## 2. Standard Safe Experiment Workflow

Before editing any file inside the lab:

1. **Create a Git checkpoint** on the experimental branch:
   ```bash
   git add -A && git commit -m "checkpoint: before <experiment>"
   ```
2. **Capture a BEFORE snapshot** with `lab_rollback.py`:
   ```bash
   python3 lab_rollback.py begin-change --id exp-001 --reason "Describe why" server.py
   ```
3. **Make your local modification**, then **record the AFTER snapshot & unified diff**:
   ```bash
   python3 lab_rollback.py commit-change --id exp-001
   ```
   - Snapshots are stored under `.lab_backups/snapshots/exp-001/{before,after,diff.patch}`.
   - Change history is appended to `.lab_backups/changelog.jsonl` and `.lab_backups/CHANGELOG.md`.

---

## 3. Reverting an Individual Change

To undo only one recorded experiment without wiping everything else:

```bash
python3 lab_rollback.py revert-change exp-001
```

---

## 4. Verifying Baseline Integrity & Tests

At any time, verify whether the workspace matches the immutable baseline and passes all tests:

```bash
python3 lab_rollback.py verify
```

---

## 5. Git-Level Rollback (Secondary Safety Layer)

- View local commits and checkpoints: `git log --oneline`
- Restore a single file from the clean `main` baseline: `git checkout main -- <file>`
- Reset the experimental branch to `main` (local only, never force-push): `git switch experiment/security-lab && git reset --hard main`
