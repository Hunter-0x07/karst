# Contributing

Karst is developed in short-lived branches and merged through pull requests.
`main` is protected: direct pushes are rejected.

## Ground rules

1. **Never push to `main`.** Every change goes through a pull request.
2. **One change per branch.** Keep a branch alive for less than two days; split large work into smaller PRs.
3. **Every PR needs an approval** from someone other than the author before it can be merged.
4. **Never commit secrets or target data.** `.env`, keys, credentials, scan output, evidence, and local scope files are ignored by `.gitignore` and must stay out of Git history.

## Setup

```bash
git clone https://github.com/Hunter-0x07/karst.git
cd karst
git config user.name "Your Name"
git config user.email "you@example.com"
```

If you prefer SSH, add your key to GitHub and verify it with `ssh -T git@github.com`.

## Daily workflow

### 1. Update `main`

```bash
git switch main
git pull --ff-only
```

`--ff-only` refuses to create a merge commit on your local `main`.

### 2. Create a branch

```bash
git switch -c feat/recon-engine
```

### 3. Commit in small steps

```bash
git status
git diff
git add -A
git commit -m "feat: add scanner plugin interface"
```

Review `git status` before staging: it is the last cheap check against committing local secrets or generated output.

### 4. Push the branch

```bash
git push -u origin feat/recon-engine
```

### 5. Open a pull request

Use the link printed by `git push`, or open:

```text
https://github.com/Hunter-0x07/karst/compare/main...feat/recon-engine?expand=1
```

With the GitHub CLI installed (`gh auth login` first):

```bash
gh pr create --fill
```

The PR title should say what changed. The description should say how it was verified, including commands, results, and known limitations.

### 6. Review

A reviewer reads `Files changed`, comments on lines, and chooses **Approve**.
Address comments with new commits. Pushing after an approval dismisses it, so request a fresh review.

### 7. Merge

Use **Squash and merge**, then **Delete branch**. Merge and rebase buttons are disabled for this repository.

### 8. Clean up locally

```bash
git switch main
git pull --ff-only
git branch -D feat/recon-engine
```

`-D` is required after a squash merge: Git does not see the squashed commit as an ancestor of the branch, so `-d` reports "not fully merged".

## Branch naming

| Prefix | Use |
|---|---|
| `feat/` | New capability |
| `fix/` | Bug fix |
| `docs/` | Documentation |
| `chore/` | Dependencies, configuration, tooling |

## Commit messages

Use `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, or `chore:` followed by a short imperative summary.

## Keeping a branch current

If `main` moves while your branch is open, rebase before requesting review:

```bash
git fetch origin
git rebase origin/main
```

Resolve conflicts, then:

```bash
git add .
git rebase --continue
git push --force-with-lease
```

`--force-with-lease` only overwrites your own branch when the remote has not moved unexpectedly. Never force-push `main`.

## Pull request size

Keep a PR under roughly 400 changed lines when possible. Large PRs receive worse review and take longer to merge.

## When something goes wrong

```bash
git status               # current state
git log --oneline -5     # recent commits
git rebase --abort       # abandon an in-progress rebase
```

Do not force-push or reset a shared branch to recover. Ask for help with the output of `git status`.
