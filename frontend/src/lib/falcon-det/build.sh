#!/bin/bash
# Build Algorand's Deterministic Falcon-1024 as WASM via Emscripten.
# Run from the falcon-det directory.
set -e

CSRC="c-src"
OUT="dist"
mkdir -p "$OUT"

# All C source files needed
SOURCES=(
  "$CSRC/codec.c"
  "$CSRC/common.c"
  "$CSRC/fft.c"
  "$CSRC/fpr.c"
  "$CSRC/keygen.c"
  "$CSRC/rng.c"
  "$CSRC/shake.c"
  "$CSRC/sign.c"
  "$CSRC/vrfy.c"
  "$CSRC/falcon.c"
  "$CSRC/deterministic.c"
  "glue.c"
)

emcc "${SOURCES[@]}" \
  -I"$CSRC" \
  -O3 \
  -s WASM=1 \
  -s MODULARIZE=1 \
  -s EXPORT_ES6=1 \
  -s EXPORT_NAME="FalconDetModule" \
  -s EXPORTED_FUNCTIONS='["_falcon_det_keygen","_falcon_det_sign","_falcon_det_verify","_falcon_det_pubkey_size","_falcon_det_privkey_size","_falcon_det_sig_maxsize","_malloc","_free"]' \
  -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap","HEAPU8","setValue","getValue"]' \
  -s ALLOW_MEMORY_GROWTH=1 \
  -s INITIAL_MEMORY=16777216 \
  -s STACK_SIZE=1048576 \
  -s ENVIRONMENT='web,worker,node' \
  -s SINGLE_FILE=1 \
  -o "$OUT/falcon-det.mjs"

echo "Build complete: $OUT/falcon-det.js + $OUT/falcon-det.wasm"
echo "Public key size: $(grep -c '' /dev/null 2>/dev/null || true)"
