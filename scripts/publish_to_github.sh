#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/Unknown-sir/IronBot.git"

if ! command -v git >/dev/null 2>&1; then
  echo "git is not installed. Install git first."
  exit 1
fi

if [ ! -d .git ]; then
  git init
fi

git add .
if git diff --cached --quiet; then
  echo "No changes to commit."
else
  git commit -m "Initial Iron Bot release"
fi

git branch -M main
if git remote get-url origin >/dev/null 2>&1; then
  git remote set-url origin "$REPO_URL"
else
  git remote add origin "$REPO_URL"
fi

echo "Pushing to $REPO_URL"
git push -u origin main
