#!/usr/bin/env bash
#
# mayhem/test.sh — RUN dislocker's AUTHORED behavioral oracle (built by mayhem/build.sh
# as /mayhem/dislocker_selftest). Upstream ships no real test suite (its only CMake
# "test" target just runs each tool with -h), so this known-answer oracle stands in:
# crc32 vectors + AES-XTS/CBC/diffuser encrypt<->decrypt round-trips over libdislocker.
# It asserts BEHAVIOR (values / round-trip identity), so a no-op/exit(0) sabotage FAILS.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
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

RUNNER=/mayhem/dislocker_selftest
if [ ! -x "$RUNNER" ]; then
  echo "test.sh: $RUNNER missing — build.sh did not produce the oracle" >&2
  emit_ctrf "dislocker-selftest" 0 1
  exit 1
fi

out="$("$RUNNER" 2>&1)"; rc=$?
echo "$out"

# Parse the oracle's summary line: "SELFTEST passed=P failed=F"
passed=$(printf '%s\n' "$out" | sed -n 's/.*SELFTEST passed=\([0-9]*\) failed=[0-9]*.*/\1/p' | tail -1)
failed=$(printf '%s\n' "$out" | sed -n 's/.*SELFTEST passed=[0-9]* failed=\([0-9]*\).*/\1/p' | tail -1)

# If the summary is absent (e.g. the binary was neutered to exit(0) before main),
# treat it as a failure so the oracle is provably behavioral.
if [ -z "$passed" ] || [ -z "$failed" ]; then
  echo "test.sh: no SELFTEST summary emitted (rc=$rc)" >&2
  emit_ctrf "dislocker-selftest" 0 1
  exit 1
fi

emit_ctrf "dislocker-selftest" "$passed" "$failed"
