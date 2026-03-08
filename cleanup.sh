#!/bin/bash
# BotScanner SVN cleanup script
# Ensures deterministic, audit-transparent working copy hygiene

set -e

echo "=== BotScanner SVN Cleanup ==="

# Step 1: Remove already-versioned junk but keep local copies
for path in __pycache__ .venv venv .vscode .idea Logs dist build *.egg-info; do
  if svn info "$path" >/dev/null 2>&1; then
    echo "Untracking $path from SVN..."
    svn delete --keep-local "$path" || true
  fi
done

# Step 2: Apply ignore rules
cat > ignore-list.txt <<'EOF'
__pycache__/
*.pyc
*.pyo
*.pyd
venv/
.venv/
env/
.vscode/
.idea/
*.swp
.DS_Store
Thumbs.db
Logs/
*.log
tmp/
*.tmp
.mypy_cache/
.pytest_cache/
dist/
build/
*.egg-info/
.svn/
.env
EOF

echo "Applying svn:ignore..."
svn propset svn:ignore -F ignore-list.txt .

# Step 3: Commit property change
svn commit -m "Cleanup BotScanner repo: remove junk, set svn:ignore"

# Step 4: Verify
echo "=== SVN Status After Cleanup ==="
svn status

echo "Cleanup complete. Repo is now audit-transparent."