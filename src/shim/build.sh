#!/bin/sh
set -eu
SRC="$(dirname "$0")/env-shim.c"
OUT="${1:-$(dirname "$0")/../../images/libscriptjail.so}"
mkdir -p "$(dirname "$OUT")"
cc -Wall -Wextra -O2 -fPIC -shared -fvisibility=hidden \
   -D_GNU_SOURCE \
   -o "$OUT" "$SRC" \
   -ldl -lpthread
echo "Built: $OUT"
