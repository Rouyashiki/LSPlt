#!/usr/bin/env bash
set -euo pipefail
src="$(cd "$(dirname "$0")/../../lsplt/src/main/jni" && pwd)"
tests="$(cd "$(dirname "$0")" && pwd)"
build="${LSPLT_TEST_BUILD:-$(mktemp -d)}"
mkdir -p "$build"
flags=(-std=c++17 -D_GNU_SOURCE -DLOG_DISABLED -DDT_ANDROID_REL=0x6000000f -DDT_ANDROID_RELSZ=0x60000010 -DDT_ANDROID_RELA=0x60000011 -DDT_ANDROID_RELASZ=0x60000012 -O1 -g -pthread -I"$src" -I"$tests")
clang++ "${flags[@]}" -fsanitize=address,undefined -fno-omit-frame-pointer "$tests/transaction_test.cpp" "$src/elf_util.cc" -o "$build/transactions-sanitized"
"$build/transactions-sanitized"
if [[ "${1:-}" == --qemu ]]; then
    for arch in aarch64 arm; do
        if [[ "$arch" == aarch64 ]]; then compiler=aarch64-linux-gnu-g++; else compiler=arm-linux-gnueabihf-g++; fi
        "$compiler" "${flags[@]}" -static "$tests/transaction_test.cpp" "$src/elf_util.cc" -o "$build/transactions-$arch"
        "qemu-$arch" "$build/transactions-$arch"
    done
fi
