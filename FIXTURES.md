# Fixtures, Tests & Findings — Solana Spike

Quick reference for the Phase 2 spike. For the full context see `../SOLANA_INTEGRATION_PLAN.md` (Findings section).

## Fixtures

| Fixture | Source | Size | Purpose |
|---|---|---|---|
| `WIRE_PROOF` | `modules/pallets/beefy-consensus-proofs/src/benchmarking.rs:39` | 808 B | Real Hyperbridge BEEFY wire proof (`[0x01] ++ SCALE(Sp1BeefyProof)`). Same proof as `evm/test/SP1BeefyTest.sol::testVerifySp1Optional`. |
| `TRUSTED_STATE_SCALE` | `modules/pallets/beefy-consensus-proofs/src/benchmarking.rs:37` | 128 B | SCALE-encoded `ConsensusState` matching `WIRE_PROOF`. `next_authorities.id` rewritten 0x1276 → 0x1275 to exercise the rotation path. |
| Vkey hash | `FIXTURE_VKEY` in same file, line 41 | 32 B | `0x0059fd0bff44da77999bb7974cbcf2ac7dc89e5869352f20a2f3cd46c9f53d5c` |
| `fibonacci_proof.bin` | `succinctlabs/sp1-solana` master, `proofs/fibonacci_proof.bin` | 1415 B (bincode) | Fallback smoke-test proof. Not currently used — kept as a known-good v5 reference. |
| v6.1.0 Groth16 VK | `succinctlabs/sp1` v6.1.0 `crates/verifier/vk-artifacts/groth16_vk.bin` | 492 B | Byte-identical to polytope-labs fork. Needed for the Path A port. sha256 `4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696`. |

Both `WIRE_PROOF` and `TRUSTED_STATE_SCALE` are inlined as hex constants in `scripts/src/main.rs` — the script has no runtime dependency on the hyperbridge crates, so the `solana/` workspace stays clean of `polkadot-sdk`.

## Tests

### `solana/scripts/src/main.rs`

Host-side harness that:
1. Hex-decodes the two fixtures.
2. Strips `PROOF_TYPE_SP1` prefix, SCALE-decodes `Sp1BeefyProof` and `ConsensusState` via **locally replicated structs** (same byte layout as `modules/consensus/beefy/primitives/src/lib.rs`, no polkadot-sdk pull-in).
3. Picks the correct authority set by matching `validator_set_id` against current/next — mirrors `modules/consensus/beefy/verifier/src/sp1.rs:60-66`.
4. Builds Solidity-ABI-encoded `PublicInputs { authorities_root, authorities_len, leaf_hash, headers[] }` — mirrors `sp1.rs:77-83` byte-for-byte (Keccak-256 over `mmr_leaf.encode()` and each `header.header`; `keyset_commitment` used raw, no hash).
5. Invokes the program via `solana-program-test` (native Rust simulator — fine for verify-or-not, **not authoritative for CU**).

Run:
```
cd solana/scripts && cargo run --release
```

### `solana/programs/sp1-verify-spike/src/lib.rs`

Minimal on-chain program. Borsh-deserializes `{ proof: Vec<u8>, sp1_public_inputs: Vec<u8> }`, calls `sp1_solana::verify_proof` with the BEEFY vkey hash constant.

## Findings

### Decoded sizes (real BEEFY data, 1 parachain header)

| Slice | Bytes |
|---|---|
| Wire proof (SCALE + type prefix) | 808 |
| Inner Groth16 proof | **356** |
| ABI-encoded public inputs | 256 |
| Parachain header (SCALE Substrate header) | 313 |
| Header count | 1 (para_id 3367) |

### Smoke test result

- SCALE decode: works.
- Public-input construction: works.
- `sp1_solana::verify_proof`: **fails** with `InvalidInstructionData` — not a bug in our code, a version incompatibility (below).

### Blocker: SP1 v5 vs v6 proof format

Hyperbridge pins `sp1-verifier` at `polytope-labs/v6.1.0-wasm-compatible` (`modules/consensus/beefy/verifier/Cargo.toml:22`). `sp1-solana` master only handles v5 proofs. v6 prepends 96 B of `exit_code` / `vk_root` / `proof_nonce` between the selector and the Groth16 point triple, and expanded Groth16 public inputs from 2 to 5. Circuit proves a different statement — no slicing trick works.

Resolution: Path A — port `sp1-solana` to v6.1.0. ~1–1.5 days. Full 6-step recipe in `../SOLANA_INTEGRATION_PLAN.md`.

### Answer to "can we use SP1 zkproof on Solana?"

**Yes.** The cryptography works (BN254 syscalls, ~280K CU for verify). Hyperbridge's v6 proofs need a small, scoped port to `sp1-solana`. Payload size forces a buffer-account tx pattern. No fundamental blockers.
