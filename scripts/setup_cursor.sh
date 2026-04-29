#!/usr/bin/env bash
# setup_cursor.sh
# Wires Cursor's rules and skills directories to the canonical ai/ directory.
#
# Creates per-file symlinks inside .cursor/rules/ and .cursor/skills/ so that:
#   - Shared rules from ai/rules/ are available to Cursor automatically
#   - .cursor/ remains a real gitignored directory, letting you add personal
#     .mdc rule files to .cursor/rules/ without committing them to the repo
#
# Safe to re-run: adds symlinks for new shared rules, removes stale ones,
# and leaves personal (non-symlink) files untouched.

set -euo pipefail

# Link every .mdc in <src_dir>/ into <dest_dir>/ and remove stale symlinks.
# Arguments:
#   $1 - subdir  : relative name used in display paths (e.g. "rules")
#   $2 - src_dir : absolute path to the source .mdc directory (ai/<subdir>/)
#   $3 - dest_dir: absolute path to the symlink directory (.cursor/<subdir>/)
# Outputs:
#   Writes progress lines to stdout.
# Returns:
#   0 on success; non-zero if mkdir, ln, or rm fails.
sync_dir() {
  local -r subdir="$1"
  local -r src_dir="$2"
  local -r dest_dir="$3"
  local src_file filename dest_file rel_target

  mkdir -p "${src_dir}" "${dest_dir}"

  # Create or refresh symlinks for all shared .mdc files.
  for src_file in "${src_dir}"/*.mdc; do
    [[ -e "${src_file}" ]] || continue
    filename="$(basename "${src_file}")"
    dest_file="${dest_dir}/${filename}"
    rel_target="../../ai/${subdir}/${filename}"

    if [[ -L "${dest_file}" ]]; then
      [[ "$(readlink "${dest_file}")" == "${rel_target}" ]] && continue
      echo "    Updating: .cursor/${subdir}/${filename}"
      rm "${dest_file}"
    elif [[ -e "${dest_file}" ]]; then
      echo "    Skipping: .cursor/${subdir}/${filename} (personal file)"
      continue
    fi

    ln -s "${rel_target}" "${dest_file}"
    echo "    Linked:   .cursor/${subdir}/${filename} -> ai/${subdir}/${filename}"
  done

  # Remove symlinks for deleted shared rules.
  for dest_file in "${dest_dir}"/*.mdc; do
    [[ -L "${dest_file}" ]] || continue
    filename="$(basename "${dest_file}")"
    [[ -e "${src_dir}/${filename}" ]] && continue
    echo "    Removed:  .cursor/${subdir}/${filename} (source deleted)"
    rm "${dest_file}"
  done
}

# Entry point. Resolves the repo root and syncs rules and skills symlinks.
# Arguments:
#   None (extra arguments are accepted and ignored).
# Outputs:
#   Writes progress and summary lines to stdout.
# Returns:
#   0 on success; non-zero if any sync_dir call fails.
main() {
  local repo_root
  repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  local -r cursor_dir="${repo_root}/.cursor"
  local -r ai_dir="${repo_root}/ai"

  echo "==> Setting up Cursor symlinks for $(basename "${repo_root}")"

  local subdir
  for subdir in rules skills; do
    sync_dir "${subdir}" "${ai_dir}/${subdir}" "${cursor_dir}/${subdir}"
  done

  echo ""
  echo "Done. Cursor loads shared rules from ai/rules/ via .cursor/rules/ symlinks."
  echo "Add personal .mdc files directly to .cursor/rules/ — they are gitignored"
  echo "and will not be touched when you re-run this script."
}

main "$@"
