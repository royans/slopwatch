#!/usr/bin/env bash
# Install Git pre-commit hook in Sentinel repository
set -e

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
HOOK_DIR="$REPO_ROOT/.git/hooks"

if [ ! -d "$HOOK_DIR" ]; then
    echo "❌ Error: Not a git repository or .git/hooks directory not found at: $HOOK_DIR"
    exit 1
fi

cp "$REPO_ROOT/.githooks/pre-commit" "$HOOK_DIR/pre-commit"
chmod +x "$HOOK_DIR/pre-commit"

echo "✅ Sentinel pre-commit hook installed successfully into: $HOOK_DIR/pre-commit"
echo "   Every 'git commit' will now automatically block secrets, local paths, and AI instructions."
