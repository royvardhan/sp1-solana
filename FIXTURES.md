# Fixtures, Tests & Findings — Solana Spike

Quick reference for the SP1 v6 → `groth16-solana` direct adapter. For full context see `../SOLANA_INTEGRATION_PLAN.md` (Findings section).

## Fixtures

| Fixture | Source | Size | Purpose |
|---|---|---|---|
| `WIRE_PROOF` (inlined hex in `scripts/src/main.rs`) | `modules/pallets/beefy-consensus-proofs/src/benchmarking.rs:39` | 808 B | Real Hyperbridge BEEFY SP1 v6 wire proof (`[PROOF_TYPE_SP1=0x01] ++ SCALE(Sp1BeefyProof)`). Inner Groth16 proof = 356 B. |
| `TRUSTED_STATE_SCALE` (inlined hex) | `benchmarking.rs:37` | 128 B | SCALE-encoded `ConsensusState` paired with the fixture. |
| `FIXTURE_VKEY` (inlined hex) | `benchmarking.rs:41` | 32 B | Hyperbridge's SP1 circuit vkey hash (`0x0059fd0bff44…`). |
| `proofs/groth16_vk_v6_1_0.bin` | `succinctlabs/sp1@v6.1.0/crates/verifier/vk-artifacts/groth16_vk.bin` | 492 B | SP1 v6.1.0 Groth16 BN254 verifying key. sha256 `4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696`. Byte-identical to polytope-labs fork. |
| `VK_ROOT_V6_1_0_BYTES` (const in `programs/sp1-verify-spike/src/vk.rs`) | Extracted from fixture proof at offset `[36..68]` | 32 B | `0x002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352`. Upstream computes this dynamically from `VerifierRecursionVks::default().root()`; we hardcode per SP1 version. |
| `proofs/naive_consensus_message.bin` | generated from live Polkadot RPC (see `../modules/consensus/beefy/prover/tests/dump_naive_fixture.rs`) | 33,985 B | Historical — from earlier naive-path exploration. Not used by the SP1 adapter; retained for reference. |
| `proofs/naive_trusted_state.bin` | same | 128 B | Same — historical. |

## Tests

### `solana/scripts/src/main.rs` — host smoke test

End-to-end verification of the real BEEFY fixture through our SP1 v6 adapter:

1. Hex-decode `TRUSTED_STATE_SCALE` and `WIRE_PROOF`.
2. SCALE-decode `Sp1BeefyProof` (via locally replicated types, no polkadot-sdk pull-in).
3. Build Solidity-ABI `PublicInputs` via alloy-sol-types — byte-identical to `modules/consensus/beefy/verifier/src/sp1.rs:77-83`.
4. Call `verify_sp1_v6(proof, public_inputs, sp1_vkey_hash, &VK_ROOT_V6_1_0_BYTES, &[0u8; 32])`.
5. Assert the pairing check passes.

Run:
```
cd solana/scripts && cargo run --release
```

### `solana/programs/sp1-verify-spike` — on-chain program

Minimal Solana program with an `entrypoint!` calling `verify_sp1_v6`. Instruction-data layout:

```
[0..32]    sp1_vkey_hash        (32 B)
[32..36]   proof_len            (u32, big-endian)
[36..36+p] proof                (356 B for v6)
[36+p..]   sp1_public_inputs    (Solidity-ABI-encoded BEEFY PublicInputs, 256 B for 1 header)
```

Build for Solana BPF:
```
cd solana && cargo build-sbf --manifest-path programs/sp1-verify-spike/Cargo.toml
```

Produces `target/deploy/sp1_verify_spike.so` (~140 KB).

## Findings

### Verified dimensions

| Slice | Bytes |
|---|---|
| Wire proof (`[0x01] ++ SCALE(Sp1BeefyProof)`) | 808 |
| Inner v6 Groth16 proof | 356 |
| Solidity-ABI public inputs | 256 |
| Parachain header | varies (313 in this fixture) |
| Groth16 VK | 492 |
| Compiled program (.so) | ~143,520 |

### Tx-size envelope

Instruction data: `32 + 4 + 356 + 256 = 648 B`.
Plus Solana tx framing: ~800 B total. **Under the 1232-B cap** — single-header BEEFY fits in one tx without a buffer-account pattern. Multi-header would still need one.

### Smoke test result

- SCALE decode: **works**.
- Public-input construction: **works** (byte-faithful port of the EVM verifier's logic).
- `verify_sp1_v6` (groth16-solana direct): **passes** on the real fixture.
  - `exit_code`: 0x00…
  - `vk_root`: 0x002f850ee9…
  - `proof_nonce`: 0x00…

### BPF build

`cargo build-sbf` succeeds with 0 errors (only cosmetic `cfg` warnings from `solana_program::entrypoint!`). Dep tree (arkworks BN254 + groth16-solana + num-bigint) all compile for `sbpf-solana-solana`.

### What's still unproven

- Actual CU cost on-chain (need deploy + tx submission on `solana-test-validator`).
- Multi-header BEEFY proofs (1 header measured; n > 1 requires re-generated fixtures).
