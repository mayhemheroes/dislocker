#!/usr/bin/env bash
#
# mayhem/build.sh — build dislocker's fuzz harnesses + standalone reproducers + the
# authored behavioral oracle. Runs inside the commit image as `mayhem` in /mayhem.
#
# Targets:
#   dis-crypt-new   in-process libFuzzer harness over the sector crypto layer
#                   (mayhem/fuzz_dis_crypt_new.c)
#   dislocker-bek   the upstream .bek parser CLI (build/src/dislocker-bek), file-input
#
# The project (libdislocker) is built once with $SANITIZER_FLAGS + $DEBUG_FLAGS so the
# fuzzed code is instrumented, and a SECOND time with normal flags for the oracle so
# test.sh stays an honest functional check (won't false-fail on benign UB).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — unset when empty.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
INC="$SRC/include"

# ---------------------------------------------------------------------------
# 1) Sanitized project build (libdislocker.so + the dislocker-bek CLI target).
#    FUSE/Ruby off: unneeded for our targets, keeps the dep surface minimal.
#    -fsanitize=fuzzer-no-link instruments the LIBRARY with SanitizerCoverage so
#    the in-process libFuzzer harness actually gets edge feedback from libdislocker
#    (without it the fuzzer only sees the harness TU -> a handful of edges).
# ---------------------------------------------------------------------------
rm -rf "$SRC/build"
cmake -S "$SRC" -B "$SRC/build" \
	-DWITH_FUSE=OFF -DWITH_RUBY=OFF \
	-DCMAKE_BUILD_TYPE=None \
	-DCMAKE_C_COMPILER="$CC" \
	-DCMAKE_C_FLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
cmake --build "$SRC/build" -j"$MAYHEM_JOBS"

SAN_LIBDIR="$SRC/build/src"

# ---------------------------------------------------------------------------
# 2) dis-crypt-new harness — fuzzer binary + standalone reproducer.
#    Both link the sanitized libdislocker.so (rpath baked to its in-image path).
# ---------------------------------------------------------------------------
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
	"$SRC/mayhem/fuzz_dis_crypt_new.cpp" \
	-I"$INC" -L"$SAN_LIBDIR" -ldislocker -Wl,-rpath,"$SAN_LIBDIR" \
	-o /mayhem/fuzz_dis_crypt_new

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -x c "$STANDALONE_FUZZ_MAIN" -x c++ \
	"$SRC/mayhem/fuzz_dis_crypt_new.cpp" \
	-I"$INC" -L"$SAN_LIBDIR" -ldislocker -Wl,-rpath,"$SAN_LIBDIR" \
	-o /mayhem/fuzz_dis_crypt_new-standalone

# ---------------------------------------------------------------------------
# 3) Oracle build — a SEPARATE, clean (non-sanitized) libdislocker with the
#    project's normal flags, so test.sh only RUNS the pre-built self-test.
# ---------------------------------------------------------------------------
rm -rf "$SRC/build-tests"
cmake -S "$SRC" -B "$SRC/build-tests" \
	-DWITH_FUSE=OFF -DWITH_RUBY=OFF \
	-DCMAKE_BUILD_TYPE=None \
	-DCMAKE_C_COMPILER="$CC" \
	-DCMAKE_C_FLAGS="$COVERAGE_FLAGS"
cmake --build "$SRC/build-tests" -j"$MAYHEM_JOBS" --target dislocker

TEST_LIBDIR="$SRC/build-tests/src"
$CC -O2 $COVERAGE_FLAGS "$SRC/mayhem/selftest.c" \
	-I"$INC" -L"$TEST_LIBDIR" -ldislocker -Wl,-rpath,"$TEST_LIBDIR" \
	-o /mayhem/dislocker_selftest

echo "build.sh: done"
ls -l /mayhem/fuzz_dis_crypt_new /mayhem/fuzz_dis_crypt_new-standalone \
	/mayhem/dislocker_selftest "$SAN_LIBDIR/dislocker-bek"
