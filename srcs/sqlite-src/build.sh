#!/usr/bin/env bash
set -euo pipefail

# Build SQLite amalgamation into LLVM bitcode (.bc) and readable .ll.
# This avoids per-file duplication issues by generating sqlite3.c via Tcl script.
#
# Requirements:
#   - tclsh (macOS has it by default)
#   - clang, llvm-link, llvm-dis on PATH
#   - On macOS, an SDK (xcode-select --install) to satisfy sysroot
#
# Usage:
#   cd bcs/sqlite-src
#   bash build.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${ROOT_DIR}/build-bc"
mkdir -p "${OUT_DIR}"

echo "Generating amalgamation (sqlite3.c) via Makefile.linux-generic (builds tools, tsrc, fts5, dummy sqlite_cfg.h)..."
cd "${ROOT_DIR}"
VERSION_STR="$(cat VERSION | tr -d '[:space:]')"
make -f Makefile.linux-generic sqlite3.c PACKAGE_VERSION="${VERSION_STR}" B.tclsh="tclsh"

# macOS sysroot (optional but recommended to avoid SDK warnings)
SDKROOT="$(xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"
SYSROOT_FLAGS=""
if [[ -n "${SDKROOT}" ]]; then
  SYSROOT_FLAGS="-isysroot ${SDKROOT}"
fi

echo "Compiling sqlite3.c to LLVM bitcode..."
clang -c -emit-llvm -O0 \
  -g -fno-discard-value-names -Xclang -disable-O0-optnone \
  -DSQLITE_OS_UNIX=1 -DSQLITE_THREADSAFE=1 \
  ${SYSROOT_FLAGS} \
  -o "${OUT_DIR}/sqlite3.bc" "${ROOT_DIR}/sqlite3.c"

echo "Linking whole_program.bc (single input)..."
llvm-link "${OUT_DIR}/sqlite3.bc" -o "${OUT_DIR}/whole_program.bc"

echo "Disassembling to whole_program.ll..."
llvm-dis -o "${OUT_DIR}/whole_program.ll" "${OUT_DIR}/whole_program.bc"

echo "Done:"
echo "  ${OUT_DIR}/whole_program.bc"
echo "  ${OUT_DIR}/whole_program.ll"


