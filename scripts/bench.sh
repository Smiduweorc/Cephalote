#!/usr/bin/env bash
# Benchmark cephalote against real-world repositories.
#
# Clones a fixed set of open-source targets (shallow), scans each one
# RUNS times with a warmup, and reports min/median/max wall time, peak
# RSS, and finding counts. Fails if any default scan's median exceeds
# BUDGET_S seconds, so this doubles as a performance regression gate.
#
# Env:
#   BIN         path to the cephalote binary   (default: ./cephalote)
#   WORK_DIR    where targets are cloned       (default: $RUNNER_TEMP or /tmp)
#   RUNS        timed runs per target          (default: 5)
#   BUDGET_S    per-target median budget, sec  (default: 90)
set -euo pipefail

BIN="${BIN:-./cephalote}"
WORK_DIR="${WORK_DIR:-${RUNNER_TEMP:-/tmp}/cephalote-bench-targets}"
RUNS="${RUNS:-5}"
BUDGET_S="${BUDGET_S:-90}"

# target-name  github-repo  description
TARGETS=(
  "flask       pallets/flask          Python, small"
  "django      django/django          Python, medium"
  "openssl     openssl/openssl        C, crypto-dense"
  "gitea       go-gitea/gitea         Go, large"
  "kubernetes  kubernetes/kubernetes  Go, huge"
)

mkdir -p "$WORK_DIR"
for t in "${TARGETS[@]}"; do
  read -r name repo _ <<<"$t"
  if [ ! -d "$WORK_DIR/$name" ]; then
    echo "Cloning $repo ..."
    git clone --depth 1 --quiet "https://github.com/$repo.git" "$WORK_DIR/$name" &
  fi
done
wait

echo
echo "Host: $(nproc) CPUs, $(awk '/MemTotal/{printf "%.1f GB RAM", $2/1048576}' /proc/meminfo)"
echo "CPU:  $(awk -F': ' '/model name/{print $2; exit}' /proc/cpuinfo)"
echo "Bin:  $("$BIN" --version)"
echo "Runs: $RUNS timed (plus 1 warmup) per target; budget ${BUDGET_S}s on median"
echo

peak_rss_kb() {
  python3 -c '
import subprocess, resource, sys
subprocess.run(sys.argv[1:], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
' "$@"
}

ROWS=()
FAILED=0

bench() {
  local label="$1" dir="$2" gated="$3"; shift 3
  local extra=("$@")

  local summary
  summary=$("$BIN" scan "$dir" "${extra[@]}" 2>/dev/null | tail -1) # warmup
  local files findings
  files=$(sed -n 's/^Scanned \([0-9]*\) files.*/\1/p' <<<"$summary")
  findings=$(sed -n 's/.*; \([0-9]*\) finding(s).*/\1/p' <<<"$summary")

  local rss_mb
  rss_mb=$(( $(peak_rss_kb "$BIN" scan "$dir" "${extra[@]}") / 1024 ))

  local times=() t0 t1
  for _ in $(seq "$RUNS"); do
    t0=$(date +%s.%N)
    "$BIN" scan "$dir" "${extra[@]}" >/dev/null 2>&1
    t1=$(date +%s.%N)
    times+=("$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}')")
  done
  local sorted min med max
  sorted=$(printf '%s\n' "${times[@]}" | sort -n)
  min=$(head -1 <<<"$sorted")
  max=$(tail -1 <<<"$sorted")
  med=$(sed -n "$(( (RUNS + 1) / 2 ))p" <<<"$sorted")

  local status="ok"
  if [ "$gated" = gated ] && awk -v m="$med" -v b="$BUDGET_S" 'BEGIN{exit !(m>b)}'; then
    status="OVER BUDGET"
    FAILED=1
  fi

  printf '%-34s files=%-6s findings=%-6s min=%-7s med=%-7s max=%-7s rss=%sMB %s\n' \
    "$label" "${files:--}" "${findings:--}" "${min}s" "${med}s" "${max}s" "$rss_mb" "$status"
  ROWS+=("| $label | ${files:-—} | ${findings:-—} | ${min}s | ${med}s | ${max}s | ${rss_mb} MB | $status |")
}

echo "--- default scan (text output) ---"
for t in "${TARGETS[@]}"; do
  read -r name _ desc <<<"$(sed 's/  */ /g' <<<"$t")"
  bench "$name ($desc)" "$WORK_DIR/$name" gated
done

echo
echo "--- CI-style variants (reported, not gated) ---"
bench "kubernetes --format sarif" "$WORK_DIR/kubernetes" open --format sarif
bench "django --format json" "$WORK_DIR/django" open --format json
bench "openssl --include-unknown" "$WORK_DIR/openssl" open --include-unknown

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "## Cephalote benchmark — real-world repositories"
    echo
    echo "Runner: $(nproc) vCPU, $(awk '/MemTotal/{printf "%.1f GB RAM", $2/1048576}' /proc/meminfo). $RUNS timed runs per target, median gated at ${BUDGET_S}s."
    echo
    echo "| Target | Files scanned | Findings | Min | Median | Max | Peak RSS | Status |"
    echo "|---|---|---|---|---|---|---|---|"
    printf '%s\n' "${ROWS[@]}"
  } >>"$GITHUB_STEP_SUMMARY"
fi

if [ "$FAILED" -ne 0 ]; then
  echo
  echo "FAIL: at least one target exceeded the ${BUDGET_S}s median budget" >&2
  exit 1
fi
echo
echo "PASS: all gated targets within the ${BUDGET_S}s median budget"
