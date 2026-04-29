#!/usr/bin/env bash
# setup-cursor.sh
# Wires Cursor's rules and skills directories to the canonical ai/ directory.
#
# Creates per-file symlinks inside .cursor/rules/ and .cursor/skills/ so that:
#   - Shared rules from ai/rules/ are available to Cursor automatically
#   - .cursor/ remains a real gitignored directory, letting you add personal
#     .mdc rule files to .cursor/rules/ without committing them to the repo
#
# Re-running this script is safe: it adds symlinks for new shared rules and
# removes symlinks for deleted ones, leaving any personal files untouched.
#
# Run once after cloning, and again whenever shared rules are added or removed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CURSOR_DIR="$REPO_ROOT/.cursor"
AI_DIR="$REPO_ROOT/ai"

echo "==> Setting up Cursor symlinks for $(basename "$REPO_ROOT")"

# If .cursor is currently a symlink (legacy setup), replace it with a directory.
if [ -L "$CURSOR_DIR" ]; then
  echo "    Replacing legacy .cursor symlink with a real directory..."
  rm "$CURSOR_DIR"
fi

for subdir in rules skills; do
  SRC_DIR="$AI_DIR/$subdir"
  DEST_DIR="$CURSOR_DIR/$subdir"

  # Ensure source and destination directories exist.
  mkdir -p "$SRC_DIR" "$DEST_DIR"

  # If the destination is still a directory symlink from older setup, replace it.
  if [ -L "$DEST_DIR" ]; then
    echo "    Replacing legacy .cursor/$subdir symlink with a real directory..."
    rm "$DEST_DIR"
    mkdir -p "$DEST_DIR"
  fi

  # Create a symlink for each .mdc file in ai/<subdir>/.
  for src_file in "$SRC_DIR"/*.mdc; do
    [ -e "$src_file" ] || continue   # skip if glob matched nothing
    filename="$(basename "$src_file")"
    dest_file="$DEST_DIR/$filename"
    rel_target="../../ai/$subdir/$filename"

    if [ -L "$dest_file" ]; then
      current_target="$(readlink "$dest_file")"
      if [ "$current_target" = "$rel_target" ]; then
        echo "    .cursor/$subdir/$filename  (already correct)"
        continue
      fi
      echo "    Updating stale symlink: .cursor/$subdir/$filename"
      rm "$dest_file"
    elif [ -e "$dest_file" ]; then
      echo "    SKIP: .cursor/$subdir/$filename exists as a real file (personal rule?)"
      continue
    fi

    ln -s "$rel_target" "$dest_file"
    echo "    Created .cursor/$subdir/$filename -> ai/$subdir/$filename"
  done

  # Remove symlinks that point to ai/<subdir> files that no longer exist.
  for dest_file in "$DEST_DIR"/*.mdc; do
    [ -L "$dest_file" ] || continue  # only manage symlinks, never touch real files
    filename="$(basename "$dest_file")"
    if [ ! -e "$SRC_DIR/$filename" ]; then
      echo "    Removing stale symlink: .cursor/$subdir/$filename (source deleted)"
      rm "$dest_file"
    fi
  done
done

echo ""
echo "Done. Cursor loads shared rules from ai/rules/ via .cursor/rules/ symlinks."
echo "Add personal .mdc files directly to .cursor/rules/ — they are gitignored"
echo "and will not be touched when you re-run this script."
