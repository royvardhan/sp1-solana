# Solana Spike — SP1 Verifier

Phase 2 of the Solana ISMP integration (see `../SOLANA_INTEGRATION_PLAN.md`).

Goal: measure whether the `sp1-solana` library verifies Groth16 proofs end-to-end inside a Solana program, and later measure tx-size behaviour for BEEFY-shaped payloads.

This is a **standalone Cargo workspace** (not part of the hyperbridge root workspace) to avoid dep conflicts with `polkadot-sdk`.

## Layout

- `programs/sp1-verify-spike/` — minimal on-chain program that calls `sp1_solana::verify_proof`.
- `scripts/` — host-side harness that decodes inlined BEEFY fixtures, builds Solidity-ABI public inputs, and invokes the program via `solana-program-test`. See `FIXTURES.md` for fixture sources.

## Run the smoke test

```
cd solana/scripts
cargo run --release
```

First run compiles the Solana + alloy dep tree — expect several minutes.

## Status

- [x] Scaffold
- [ ] Smoke test passes end-to-end
- [ ] CU measurement on real validator
- [ ] BEEFY payload size measurement (real / mocked)
- [ ] Buffer-account overflow pattern prototype
