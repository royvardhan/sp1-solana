# Solana Spike — SP1 Verifier

Phase 2 of the Solana ISMP integration (see `../SOLANA_INTEGRATION_PLAN.md`).

Goal: measure whether the `sp1-solana` library verifies Groth16 proofs end-to-end inside a Solana program, and later measure tx-size behaviour for BEEFY-shaped payloads.

This is a **standalone Cargo workspace** (not part of the hyperbridge root workspace) to avoid dep conflicts with `polkadot-sdk`.

## Layout

- `programs/sp1-verify-spike/` — minimal on-chain program that calls `sp1_solana::verify_proof`.
- `scripts/` — host-side harness that loads a pre-generated proof and invokes the program via `solana-program-test`.
- `proofs/fibonacci_proof.bin` — pre-generated SP1 Groth16 proof of the 20th Fibonacci number (from `succinctlabs/sp1-solana`).

## Run the smoke test

```
cd solana/scripts
cargo run --release
```

First run compiles `sp1-sdk` and friends — expect 10+ minutes.

## Status

- [x] Scaffold
- [ ] Smoke test passes end-to-end
- [ ] CU measurement on real validator
- [ ] BEEFY payload size measurement (real / mocked)
- [ ] Buffer-account overflow pattern prototype
