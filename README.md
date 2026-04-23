# Solana Spike — SP1 v6 Groth16 Verifier (BEEFY)

Phase 2B of the Solana ISMP integration (see `../SOLANA_INTEGRATION_PLAN.md`).

Goal: verify Hyperbridge's SP1 v6 BEEFY Groth16 proofs on Solana, **bypassing `sp1-solana`** (which currently only supports SP1 v2–v5) by integrating directly with Light Protocol's [`groth16-solana`](https://github.com/Lightprotocol/groth16-solana).

This is a **standalone Cargo workspace** (not part of the hyperbridge root workspace) to avoid dep conflicts with `polkadot-sdk`.

## Layout

- `programs/sp1-verify-spike/` — on-chain Solana program:
  - `src/types.rs` — SCALE-layout replicas of `Sp1BeefyProof` + `ConsensusState` (no polkadot-sdk pull-in).
  - `src/utils.rs` — proof/VK parsing (vendored from `sp1-solana`, MIT).
  - `src/vk.rs` — SP1 v6.1.0 Groth16 VK bytes + `VK_ROOT_V6_1_0_BYTES` constant.
  - `src/verifier.rs` — `verify_sp1_v6`: parses v6 proof layout, builds 5-input Groth16 public inputs, calls `groth16-solana`.
  - `src/lib.rs` — library + on-chain `entrypoint!`.
- `scripts/` — host-side smoke test that runs the real Hyperbridge BEEFY fixture through `verify_sp1_v6`.
- `proofs/` — fixtures (see `FIXTURES.md`).

## Build on-chain program

```
cd solana
cargo build-sbf --manifest-path programs/sp1-verify-spike/Cargo.toml
```

Produces `target/deploy/sp1_verify_spike.so` (~140 KB).

## Run host smoke test

```
cd solana/scripts && cargo run --release
```

Expected output ends with:
```
verification ok
  exit_code:   0x00…
  vk_root:     0x002f850ee9…
  proof_nonce: 0x00…
```

## Status

- [x] Host-side verifier works on real Hyperbridge BEEFY SP1 v6 fixture.
- [x] `cargo build-sbf` produces a deployable `.so`.
- [x] Tx-size envelope: 648 B instruction data (fits under 1232-B cap for single-header case).
- [ ] Deploy to `solana-test-validator` and measure actual CU.
- [ ] Multi-header BEEFY proofs (need fixture regeneration + possibly buffer-account pattern).
