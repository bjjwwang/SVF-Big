cd /Users/z5489735/2023/0424/Software-Security-Analysis-Marker/solution/bcs/zstd/lib
# 强制使用 LLVM 16 工具链
LLVM16_BIN="/opt/homebrew/opt/llvm@16/bin"
if [ ! -x "$LLVM16_BIN/clang" ] || [ ! -x "$LLVM16_BIN/llvm-link" ] || [ ! -x "$LLVM16_BIN/llvm-dis" ]; then
  echo "ERROR: llvm@16 not found. Install: brew install llvm@16" >&2
  exit 1
fi
export PATH="$LLVM16_BIN:$PATH"

# 版本校验（必须是 16）
CLANG_VER="$("$LLVM16_BIN/clang" --version 2>/dev/null | head -1)"
if ! echo "$CLANG_VER" | grep -qE 'version 16(\.|$)'; then
  echo "ERROR: clang is not LLVM 16: $CLANG_VER" >&2
  exit 1
fi

# 如果之前出现过 “cannot create executables”，补上 SDKROOT
SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"

# 清理旧的 bitcode（避免不同 LLVM 版本混用导致 Invalid record）
rm -rf build-bc whole_program.bc whole_program.ll

make whole_program.ll \
  CC="$LLVM16_BIN/clang" \
  LLVM_LINK="$LLVM16_BIN/llvm-link" \
  LLVM_DIS="$LLVM16_BIN/llvm-dis" \
  CFLAGS="-O0 -isysroot $SDKROOT" -j