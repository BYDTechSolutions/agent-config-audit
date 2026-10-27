#!/usr/bin/env bash
# The GitHub Action's one step (see action.yml). Inputs arrive as INPUT_* env
# vars, never pasted into the script, so their text cannot run as shell code.
# One audit writes every format: text for the log, Markdown for the job
# summary, JSON for the outputs, SARIF for code scanning.
set -uo pipefail

fail() {
  echo "::error title=agent-config-audit::$1"
  exit 2
}

command -v node >/dev/null 2>&1 || fail "Node.js 20 or newer is needed. Add actions/setup-node before this step."
major=$(node -p 'process.versions.node.split(".")[0]')
[ "$major" -ge 20 ] || fail "Node.js 20 or newer is needed, found $(node -v). Add actions/setup-node with node-version: 22 before this step."

pkg="${INPUT_PACKAGE:-}"
if [ -z "$pkg" ]; then
  version=$(node -p 'require(process.argv[1]).version' "$GITHUB_ACTION_PATH/package.json")
  pkg="@bydtech/agent-config-audit@$version"
fi

dir="${INPUT_PATH:-.}"
command="${INPUT_COMMAND:-audit}"
out="${RUNNER_TEMP:-/tmp}/agent-config-audit"
mkdir -p "$out"
rm -f "$out/report.txt" "$out/report.md" "$out/report.json"

case "$command" in
  audit)
    args=("$dir" --no-color -o "$out/report.txt" -o "$out/report.md" -o "$out/report.json")
    [ -n "${INPUT_SARIF_FILE:-}" ] && args+=(-o "$INPUT_SARIF_FILE")
    [ -n "${INPUT_BASELINE:-}" ] && args+=(--baseline "$INPUT_BASELINE")
    fail_on="${INPUT_FAIL_ON-fix-now}"
    case "$fail_on" in
      none | '') ;;
      fix-now | should-fix) args+=(--fail-on "$fail_on") ;;
      *) fail "fail-on must be fix-now, should-fix or none, got \"$fail_on\"." ;;
    esac
    ;;
  diff)
    args=(diff "$dir" --no-color -o "$out/report.txt" -o "$out/report.json")
    ;;
  *) fail "command must be audit or diff, got \"$command\"." ;;
esac
[ -n "${INPUT_ONLY:-}" ] && [ "$command" = audit ] && args+=(--only "$INPUT_ONLY")
[ -n "${INPUT_EXCLUDE:-}" ] && args+=(--exclude "$INPUT_EXCLUDE")
[ -n "${INPUT_LOCK:-}" ] && [ "$command" = diff ] && args+=(--lock "$INPUT_LOCK")
if [ -n "${INPUT_ARGS:-}" ]; then
  read -r -a extra <<< "$INPUT_ARGS"
  args+=("${extra[@]}")
fi

echo "Running $pkg"
# On Windows runners, Git Bash rewrites arguments that start with / into
# Windows paths. The two variables turn that off for npx.
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' npx --yes --package="$pkg" -- agent-config-audit "${args[@]}"
code=$?

[ -f "$out/report.txt" ] || exit "$code"
echo
cat "$out/report.txt"

summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
if [ "$command" = audit ]; then
  if [ "$(wc -c < "$out/report.md")" -lt 1000000 ]; then
    cat "$out/report.md" >> "$summary"
  else
    echo "The agent-config-audit report is too large for the job summary; it is in the log." >> "$summary"
  fi
  node -e '
const r = require(process.argv[1]);
const n = (p) => r.findings.filter((f) => f.priority === p).length;
console.log(`fix-now=${n("fix-now")}\nshould-fix=${n("should-fix")}\nreview=${n("review")}`);
' "$out/report.json" >> "${GITHUB_OUTPUT:-/dev/null}"
  {
    echo "report-json=$out/report.json"
    echo "report-md=$out/report.md"
    echo "sarif-file=${INPUT_SARIF_FILE:-}"
  } >> "${GITHUB_OUTPUT:-/dev/null}"
  [ "$code" -eq 1 ] && echo "::error title=agent-config-audit::Findings at fail-on $fail_on or above. The report is in the log and the job summary."
else
  { echo '## Agent config diff'; echo; echo '```text'; cat "$out/report.txt"; echo '```'; } >> "$summary"
  node -e 'console.log(`changes=${require(process.argv[1]).changes.length}`)' "$out/report.json" >> "${GITHUB_OUTPUT:-/dev/null}"
  echo "report-json=$out/report.json" >> "${GITHUB_OUTPUT:-/dev/null}"
  [ "$code" -eq 1 ] && echo "::error title=agent-config-audit::The agent config changed since agent-config.lock. Review the changes, then run agent-config-audit lock and commit the lockfile."
fi
exit "$code"
