#!/usr/bin/env bash
# Follow CONTRIBUTING.md the way a new contributor would, and fail naming the step that broke.
#
# It reads the commands from the fenced code blocks in the "Setup" and "Development loop"
# sections of CONTRIBUTING.md and runs them in order, in a temporary directory with a new
# virtualenv. Then it branches, makes a docs edit, commits with `git commit -s`, checks the
# sign-off, and runs `bawbel-gate --version`. A command renamed in CONTRIBUTING.md fails here.
#
# Two substitutions, both on purpose:
#   - `git clone <url>` clones THIS checkout (its committed HEAD), not GitHub's main, so the
#     script tests the change in front of you. Uncommitted changes are not tested.
#   - Nothing else is rewritten. The commands run exactly as the document gives them.
#
# Usage:
#   bash scripts/contributor_smoke.sh           run every step
#   bash scripts/contributor_smoke.sh --list    print the steps without running them
#
# Environment:
#   PYTHON              interpreter for the new virtualenv (default: python3)
#   CONTRIBUTING_FILE   the document to follow (default: CONTRIBUTING.md in this checkout)
#   KEEP=1              keep the temporary directory and print its path
#
# Needs bash, git, Python 3.10 or later, and network access (PyPI and GitHub, for the
# pre-commit hooks). Linux and macOS.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRIBUTING_FILE="${CONTRIBUTING_FILE:-$REPO_ROOT/CONTRIBUTING.md}"
PYTHON="${PYTHON:-python3}"
SECTIONS=("Setup" "Development loop")

die() { echo "FAILED: $*" >&2; exit 1; }

# The commands in the fenced blocks of one "## <section>" of CONTRIBUTING.md, one per line,
# with trailing comments and blank lines removed.
section_commands() {
  awk -v sec="$1" '
    /^## / { insec = ($0 == "## " sec); inblock = 0; next }
    insec && /^```/ { inblock = !inblock; next }
    insec && inblock { print }
  ' "$CONTRIBUTING_FILE" | sed -E '/^[[:space:]]*#/d; s/[[:space:]]+#.*$//; /^[[:space:]]*$/d'
}

[ -f "$CONTRIBUTING_FILE" ] || die "cannot read $CONTRIBUTING_FILE"

STEPS=()
for section in "${SECTIONS[@]}"; do
  found=0
  while IFS= read -r command; do
    STEPS+=("$section|$command")
    found=$((found + 1))
  done < <(section_commands "$section")
  [ "$found" -gt 0 ] || die "$(basename "$CONTRIBUTING_FILE") has no commands in a fenced block under '## $section'"
done

TOTAL="${#STEPS[@]}"

if [ "${1:-}" = "--list" ]; then
  n=0
  for entry in "${STEPS[@]}"; do
    n=$((n + 1))
    echo "step $n [${entry%%|*}] ${entry#*|}"
  done
  exit 0
fi
[ $# -eq 0 ] || die "unknown argument '$1' (use --list, or no argument)"

if [ -n "$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null)" ]; then
  echo "note: this checkout has uncommitted changes. They are not tested: the script clones HEAD."
fi

WORK="$(mktemp -d)"
cleanup() {
  if [ "${KEEP:-}" = "1" ]; then echo "kept: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

# A new virtualenv. Some Linux images ship a venv module without pip, so fall back to virtualenv.
"$PYTHON" -m venv "$WORK/venv" 2>/dev/null || true
if [ ! -x "$WORK/venv/bin/pip" ]; then
  rm -rf "$WORK/venv"
  command -v virtualenv >/dev/null || die "cannot create a virtualenv with pip: install python3-venv or virtualenv"
  virtualenv -q -p "$PYTHON" "$WORK/venv"
fi
export VIRTUAL_ENV="$WORK/venv"
export PATH="$WORK/venv/bin:$PATH"
export PIP_DISABLE_PIP_VERSION_CHECK=1

cwd="$WORK"
n=0
for entry in "${STEPS[@]}"; do
  n=$((n + 1))
  section="${entry%%|*}"
  command="${entry#*|}"
  echo "==> step $n/$TOTAL [$section] $command"

  if [[ "$command" =~ ^git\ clone\ [^[:space:]]+(\ .*)?$ ]]; then
    run="git clone --quiet \"$REPO_ROOT\"${BASH_REMATCH[1]}"
  elif [[ "$command" =~ ^cd\ ([^[:space:]]+)$ ]]; then
    [ -d "$cwd/${BASH_REMATCH[1]}" ] || die "step $n [$section] $command: no directory ${BASH_REMATCH[1]} after the previous steps"
    cwd="$cwd/${BASH_REMATCH[1]}"
    continue
  else
    run="$command"
  fi

  status=0
  (cd "$cwd" && bash -c "$run") || status=$?
  if [ "$status" -ne 0 ]; then
    echo "FAILED at step $n/$TOTAL [$section]: $command (exit $status)" >&2
    exit 1
  fi
done

[ -d "$cwd/.git" ] || die "after the documented steps there is no git checkout at $cwd"

contribute() {
  echo "==> contribution: $*"
}

contribute "branch, edit a docs file, commit with a sign-off"
(
  cd "$cwd"
  git switch -q -c smoke/contributor-path
  printf 'Contributor smoke test.\n' > docs/contributor-smoke-note.md
  git add docs/contributor-smoke-note.md
  GIT_AUTHOR_NAME="Smoke Test" GIT_AUTHOR_EMAIL="smoke@example.invalid" \
  GIT_COMMITTER_NAME="Smoke Test" GIT_COMMITTER_EMAIL="smoke@example.invalid" \
    git commit -s -q -m "docs: contributor smoke test"
) || { echo "FAILED at: git commit -s (the pre-commit hooks or git refused the commit)" >&2; exit 1; }

contribute "the commit carries a Signed-off-by line"
git -C "$cwd" log -1 --format=%B | grep -qx "Signed-off-by: Smoke Test <smoke@example.invalid>" \
  || { echo "FAILED at: the commit has no Signed-off-by line, so git commit -s did not sign it off" >&2; exit 1; }

contribute "bawbel-gate --version"
(cd "$cwd" && bawbel-gate --version) \
  || { echo "FAILED at: bawbel-gate --version" >&2; exit 1; }

echo "contributor path OK in ${SECONDS} seconds"
