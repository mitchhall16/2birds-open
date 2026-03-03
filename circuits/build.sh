#!/usr/bin/env bash
set -euo pipefail

# Circuit build script for algo-privacy
# Compiles Circom circuits, performs trusted setup, generates verifier keys

CIRCUIT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${CIRCUIT_DIR}/build"
PTAU_FILE_15="${BUILD_DIR}/powersOfTau28_hez_final_15.ptau"
PTAU_FILE_17="${BUILD_DIR}/powersOfTau28_hez_final_17.ptau"
PTAU_FILE="${PTAU_FILE_15}"
PTAU_URL="https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_15.ptau"

mkdir -p "${BUILD_DIR}"

echo "=== Algorand Privacy SDK — Circuit Builder ==="
echo ""

# Check dependencies
export PATH="$HOME/.cargo/bin:$PATH"
command -v circom >/dev/null 2>&1 || { echo "ERROR: circom not found. Install with: cargo install circom"; exit 1; }
command -v snarkjs >/dev/null 2>&1 || { echo "ERROR: snarkjs not found. Install with: npm install -g snarkjs"; exit 1; }

# Download Powers of Tau (Phase 1 trusted setup — reusable)
if [ ! -f "${PTAU_FILE}" ] || [ "$(wc -c < "${PTAU_FILE}" | tr -d ' ')" -lt 1000 ]; then
    rm -f "${PTAU_FILE}"
    echo "Downloading Powers of Tau (Phase 1 trusted setup)..."
    echo "This is a one-time download (~36 MB)"
    curl -L -o "${PTAU_FILE}" "${PTAU_URL}"
fi

build_circuit() {
    local name=$1
    local main_file=$2

    echo ""
    echo "--- Building circuit: ${name} ---"

    # 1. Compile Circom to R1CS + WASM
    echo "[1/5] Compiling Circom circuit..."
    local basename
    basename="$(basename "${main_file}" .circom)"
    circom "${main_file}" \
        --r1cs --wasm --sym \
        -l "${CIRCUIT_DIR}/../node_modules" \
        -o "${BUILD_DIR}"

    # Rename outputs if circom used a different name (hyphens vs underscores)
    if [ "${basename}" != "${name}" ]; then
        [ -f "${BUILD_DIR}/${basename}.r1cs" ] && mv "${BUILD_DIR}/${basename}.r1cs" "${BUILD_DIR}/${name}.r1cs"
        [ -f "${BUILD_DIR}/${basename}.sym" ] && mv "${BUILD_DIR}/${basename}.sym" "${BUILD_DIR}/${name}.sym"
        [ -d "${BUILD_DIR}/${basename}_js" ] && mv "${BUILD_DIR}/${basename}_js" "${BUILD_DIR}/${name}_js"
    fi

    # Print circuit info
    snarkjs r1cs info "${BUILD_DIR}/${name}.r1cs"

    # 2. Groth16 setup (Phase 2 — circuit-specific)
    echo "[2/5] Running Groth16 Phase 2 setup..."
    snarkjs groth16 setup \
        "${BUILD_DIR}/${name}.r1cs" \
        "${PTAU_FILE}" \
        "${BUILD_DIR}/${name}_0000.zkey"

    # 3. Contribute to Phase 2 ceremony
    # Uses /dev/urandom entropy. For production, use ceremony.sh with multi-party contributions.
    echo "[3/5] Contributing to Phase 2 ceremony..."
    head -c 64 /dev/urandom | base64 | snarkjs zkey contribute \
        "${BUILD_DIR}/${name}_0000.zkey" \
        "${BUILD_DIR}/${name}_final.zkey" \
        --name="algo-privacy-dev-$(date +%s)"

    # 4. Export verification key
    echo "[4/5] Exporting verification key..."
    snarkjs zkey export verificationkey \
        "${BUILD_DIR}/${name}_final.zkey" \
        "${BUILD_DIR}/${name}_vkey.json"

    # 5. Generate Solidity verifier (for reference — we use AlgoPlonk for AVM)
    echo "[5/5] Exporting verifier..."
    snarkjs zkey export solidityverifier \
        "${BUILD_DIR}/${name}_final.zkey" \
        "${BUILD_DIR}/${name}_verifier.sol"

    # 6. PLONK setup (parallel proof system — cheaper on-chain verification)
    echo "[6/7] Running PLONK setup..."
    snarkjs plonk setup \
        "${BUILD_DIR}/${name}.r1cs" \
        "${PTAU_FILE}" \
        "${BUILD_DIR}/${name}_plonk.zkey"

    # 7. Export PLONK verification key
    echo "[7/7] Exporting PLONK verification key..."
    snarkjs zkey export verificationkey \
        "${BUILD_DIR}/${name}_plonk.zkey" \
        "${BUILD_DIR}/${name}_plonk_vkey.json"

    echo "--- ${name} circuit built successfully ---"
    echo "  R1CS:      ${BUILD_DIR}/${name}.r1cs"
    echo "  WASM:      ${BUILD_DIR}/${name}_js/${name}.wasm"
    echo "  Groth16:   ${BUILD_DIR}/${name}_final.zkey"
    echo "  PLONK:     ${BUILD_DIR}/${name}_plonk.zkey"
    echo "  VKey:      ${BUILD_DIR}/${name}_vkey.json"
    echo "  PLONK VKey: ${BUILD_DIR}/${name}_plonk_vkey.json"
}

# Build each circuit
case "${1:-all}" in
    withdraw)
        build_circuit "withdraw" "${CIRCUIT_DIR}/withdraw.circom"
        ;;
    deposit)
        PTAU_FILE="${PTAU_FILE_17}"
        build_circuit "deposit" "${CIRCUIT_DIR}/deposit.circom"
        ;;
    range-proof)
        build_circuit "range_proof" "${CIRCUIT_DIR}/range-proof.circom"
        ;;
    privateSend)
        PTAU_FILE="${PTAU_FILE_17}"
        build_circuit "privateSend" "${CIRCUIT_DIR}/privateSend.circom"
        ;;
    shielded)
        PTAU_FILE="${PTAU_FILE_17}"
        build_circuit "shielded_transfer" "${CIRCUIT_DIR}/shielded-transfer.circom"
        ;;
    split)
        PTAU_FILE="${PTAU_FILE_17}"
        build_circuit "split" "${CIRCUIT_DIR}/split.circom"
        ;;
    combine)
        PTAU_FILE="${PTAU_FILE_17}"
        build_circuit "combine" "${CIRCUIT_DIR}/combine.circom"
        ;;
    all)
        build_circuit "withdraw" "${CIRCUIT_DIR}/withdraw.circom"
        PTAU_FILE="${PTAU_FILE_17}"
        build_circuit "deposit" "${CIRCUIT_DIR}/deposit.circom"
        PTAU_FILE="${PTAU_FILE_17}"
        build_circuit "privateSend" "${CIRCUIT_DIR}/privateSend.circom"
        PTAU_FILE="${PTAU_FILE_15}"
        build_circuit "range_proof" "${CIRCUIT_DIR}/range-proof.circom"
        PTAU_FILE="${PTAU_FILE_17}"
        build_circuit "shielded_transfer" "${CIRCUIT_DIR}/shielded-transfer.circom"
        PTAU_FILE="${PTAU_FILE_17}"
        build_circuit "split" "${CIRCUIT_DIR}/split.circom"
        PTAU_FILE="${PTAU_FILE_17}"
        build_circuit "combine" "${CIRCUIT_DIR}/combine.circom"
        ;;
    *)
        echo "Usage: $0 {withdraw|deposit|privateSend|range-proof|shielded|split|combine|all}"
        exit 1
        ;;
esac

echo ""
echo "=== All circuits built successfully ==="
echo ""
echo "Next steps:"
echo "  1. Generate PLONK verifier: npx tsx contracts/generate-plonk-verifier.ts build/<name>_plonk_vkey.json"
echo "  2. Deploy pool contracts with the verifier LogicSig"
echo "  3. Distribute proving key (.zkey) and WASM witness generator to SDK package"
echo "  4. Copy PLONK .zkey and .wasm to frontend/public/circuits/ for browser proving"
