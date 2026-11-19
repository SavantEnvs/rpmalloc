#!/usr/bin/env bash
#
# mayhem/build.sh — build the rpmalloc fuzz harnesses and the upstream test suite.
#
# rpmalloc is a single translation unit (rpmalloc/rpmalloc.c, which #includes malloc.c when
# ENABLE_OVERRIDE=1); upstream's configure.py/ninja generator is not needed, so this compiles it
# directly, the way upstream's own sanitizer CI job does. Re-runnable and offline: no fetches.
#
# Outputs:
#   /mayhem/fuzz_{alloc,heap,config,threads,override}            libFuzzer targets
#   /mayhem/fuzz_*-standalone                                    run-once reproducers
#   mayhem/out/rpmalloc-test                                     upstream test suite (normal flags)
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT="$SRC/mayhem/out"
H="$SRC/mayhem/harnesses"
mkdir -p "$OUT"

# Library configurations (all #ifndef-guarded switches in rpmalloc.c):
#   ENABLE_OVERRIDE=0        the ASan targets keep libc malloc; rpmalloc is only reached via rp*
#   ENABLE_ASSERTS=1         internal invariants abort
#   RPMALLOC_FIRST_CLASS_HEAPS=1  compiles the rpmalloc_heap_* API (also needed by the harness TU)
COMMON_DEFS="-DENABLE_OVERRIDE=0 -DENABLE_ASSERTS=1 -DRPMALLOC_FIRST_CLASS_HEAPS=1"
STATS_DEFS="$COMMON_DEFS -DENABLE_STATISTICS=1"
# The override target replaces malloc for the whole process, which collides with ASan's own
# allocator: build it with the same sanitizer flags minus AddressSanitizer (UBSan stays, halting).
OVR_DEFS="-DENABLE_OVERRIDE=1 -DENABLE_ASSERTS=1"
OVR_SAN="$(printf '%s' "$SANITIZER_FLAGS" | sed -e 's/-fsanitize=address,/-fsanitize=/g' \
  -e 's/,address\b//g' -e 's/-fsanitize=address\b//g')"

# -fsanitize=fuzzer-no-link: SanCov instrumentation for the separately compiled library and harness
# objects (LIB_FUZZING_ENGINE only links the engine).
FUZZ_COV="-fsanitize=fuzzer-no-link"
CFLAGS_FUZZ="$SANITIZER_FLAGS $FUZZ_COV $DEBUG_FLAGS -O1 -Irpmalloc"
$CC $CFLAGS_FUZZ $COMMON_DEFS -c rpmalloc/rpmalloc.c -o "$OUT/rpmalloc_fuzz.o"
$CC $CFLAGS_FUZZ $STATS_DEFS -c rpmalloc/rpmalloc.c -o "$OUT/rpmalloc_stats.o"
$CC $OVR_SAN $FUZZ_COV $DEBUG_FLAGS -O1 -Irpmalloc $OVR_DEFS -c rpmalloc/rpmalloc.c -o "$OUT/rpmalloc_override.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$OUT/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"
$CC $OVR_SAN $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main_ovr.o"

# <harness> <library object> <defines>
build_asan() {
  local name="$1" lib="$2" defs="$3"
  $CC $CFLAGS_FUZZ $defs -c "$H/$name.c" -o "$OUT/$name.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/$name.o" "$lib" "$OUT/lsan_off.o" \
    -lpthread -lm -o "$SRC/$name"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/standalone_main.o" "$OUT/$name.o" "$lib" "$OUT/lsan_off.o" \
    -lpthread -lm -o "$SRC/$name-standalone"
}
build_asan fuzz_alloc "$OUT/rpmalloc_fuzz.o" "$COMMON_DEFS"
build_asan fuzz_heap "$OUT/rpmalloc_fuzz.o" "$COMMON_DEFS"
build_asan fuzz_threads "$OUT/rpmalloc_fuzz.o" "$COMMON_DEFS"
build_asan fuzz_config "$OUT/rpmalloc_stats.o" "$STATS_DEFS"

$CC $OVR_SAN $FUZZ_COV $DEBUG_FLAGS -O1 -c "$H/fuzz_override.c" -o "$OUT/fuzz_override.o"
$CC $OVR_SAN $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/fuzz_override.o" "$OUT/rpmalloc_override.o" \
  -lpthread -lm -o "$SRC/fuzz_override"
$CXX $OVR_SAN $DEBUG_FLAGS "$OUT/standalone_main_ovr.o" "$OUT/fuzz_override.o" "$OUT/rpmalloc_override.o" \
  -lpthread -lm -o "$SRC/fuzz_override-standalone"

# Upstream test suite (test/main.c), with the defines of upstream's direct-build CI job and normal
# (unsanitized) optimization flags; mayhem/test.sh runs it.
$CC -O2 $COVERAGE_FLAGS -D_GNU_SOURCE -DENABLE_OVERRIDE=0 -DENABLE_ASSERTS=1 -DENABLE_STATISTICS=1 \
  -DRPMALLOC_FIRST_CLASS_HEAPS=1 -DRPMALLOC_TEST_YIELD_POINTS=7 -Irpmalloc -Itest \
  rpmalloc/rpmalloc.c test/thread.c test/main.c -lpthread -lm -o "$OUT/rpmalloc-test"
