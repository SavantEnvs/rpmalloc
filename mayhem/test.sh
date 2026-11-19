#!/usr/bin/env bash
#
# mayhem/test.sh — run rpmalloc's own test suite (test/main.c, built by mayhem/build.sh with
# normal flags). The suite asserts allocator behavior (block granularity, usable sizes, content
# preservation across realloc, zeroed memory, overflow checks, cross-thread frees, heap APIs,
# statistics, decommit, finalize/unmap) and prints "All tests passed" only when every check held;
# any check prints "FAIL: <reason> @ file:line". Both the exit code and that line are asserted.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

runner="$SRC/mayhem/out/rpmalloc-test"
if [ ! -x "$runner" ]; then
  echo "test runner $runner missing — mayhem/build.sh did not build it" >&2
  emit_ctrf rpmalloc-test 0 1
  exit 1
fi

log="$(mktemp)"
# RPMALLOC_TEST_SCALE is upstream's own knob for scaling per-thread loop counts (percent).
RPMALLOC_TEST_SCALE="${RPMALLOC_TEST_SCALE:-25}" "$runner" >"$log" 2>&1
rc=$?
cat "$log"
if [ "$rc" -eq 0 ] && grep -qx 'All tests passed' "$log" && ! grep -q '^FAIL: ' "$log"; then
  emit_ctrf rpmalloc-test 1 0
else
  echo "rpmalloc test suite failed (exit $rc)" >&2
  emit_ctrf rpmalloc-test 0 1
fi
