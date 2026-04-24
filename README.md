# SP1 v6 Groth16 Verifier on Solana

Verifies SP1 v6 Groth16 proofs inside a Solana program by integrating directly with Light Protocol's [`groth16-solana`](https://github.com/Lightprotocol/groth16-solana). Bypasses [`succinctlabs/sp1-solana`](https://github.com/succinctlabs/sp1-solana), which currently supports SP1 v2–v5 only.

Built while wiring Hyperbridge's BEEFY consensus proofs to Solana, but the core adapter (`programs/sp1-verify-spike/src/verifier.rs`) is BEEFY-agnostic — any SP1 v6 Groth16 proof works as long as the caller supplies the right SP1 circuit vkey hash and public inputs.

## Results (measured on `solana-test-validator`)

| | Value | Solana cap | Headroom |
|---|---|---|---|
| Compute units per verification | **278,286** | 1,400,000 | 5.0× |
| Transaction size | **859 B** | 1,232 | 1.4× |
| Program binary (`.so`) | ~143 KB | — | — |

All within Solana's hard limits, single-transaction, no buffer-account pattern needed for the measured fixture.

## Multi-header capacity

A BEEFY proof can finalize multiple parachain headers at once. The inner SP1 Groth16 proof stays 356 B regardless — only the `public_inputs` vector grows, by exactly 64 B per extra header (one Solidity-ABI `(uint256 id, bytes32 hash)` tuple). Measured by `scripts/src/tx_size_sweep.rs`:

| Headers | tx size | Headroom |
|--------:|--------:|---------:|
| 1 | 859 B | +373 |
| 3 | 987 B | +245 |
| 6 | 1179 B | +53 |
| 7 | 1243 B | **OVER** (−11) |

Up to **6 parachain headers fit in a single Solana transaction**. Beyond that, a buffer-account pattern (pre-upload public inputs, reference by address) is required. CU cost is essentially flat across N because SP1 v6 always commits to exactly 5 Groth16 public inputs regardless of inner circuit shape — per-header growth is only a handful of CU from hashing the slightly larger ABI payload.

## Layout

- `programs/sp1-verify-spike/` — on-chain Solana program. `verifier.rs` is the SP1 v6 entrypoint.
- `scripts/` — three binaries:
  - `sp1-verify-spike-script` — host-side smoke test (runs the verifier natively for quick iteration).
  - `onchain-tx` — deploys to a live validator, submits a real tx, reads consumed CU from the receipt.
  - `tx-size-sweep` — builds (never submits) transactions with N = 1..=10 synthesized headers and reports wire size. No validator needed.
- `proofs/` — fixtures. See [`FIXTURES.md`](./FIXTURES.md).

## Build

Requires: Rust (stable), Solana CLI 3.1+.

```sh
# Host smoke test
cd scripts && cargo run --release --bin sp1-verify-spike-script

# Solana BPF build (produces target/deploy/sp1_verify_spike.so)
cargo build-sbf --manifest-path programs/sp1-verify-spike/Cargo.toml

# Multi-header tx-size sweep (no validator required)
cd scripts && cargo run --release --bin tx-size-sweep
```

## Run end-to-end on a local validator

```sh
# Terminal 1:
solana-test-validator --reset

# Terminal 2:
solana config set --url http://127.0.0.1:8899
solana airdrop 10
solana program deploy target/deploy/sp1_verify_spike.so
# Note the Program Id printed here.

PROGRAM_ID=<program-id> cargo run --release --bin onchain-tx
```

Successful output ends with:

```
Program log: sp1 v6 beefy groth16 verification ok
CONSUMED COMPUTE UNITS: 278286
```

## How the adapter works

SP1 v6's `.bytes()` output packs 356 bytes into this layout:

```
[0..4]     sha256(groth16_vk)[..4]       — vk fingerprint selector
[4..36]    exit_code                      — 32 B  (NEW in v6)
[36..68]   vk_root                        — 32 B  (NEW in v6)
[68..100]  proof_nonce                    — 32 B  (NEW in v6)
[100..356] πA || πB || πC (G1||G2||G1)    — 256 B uncompressed
```

The Groth16 public-input vector grew from 2 elements (v5) to 5 elements (v6):

```
[sp1_vkey_hash, hash(sp1_public_inputs), exit_code, vk_root, proof_nonce]
```

`verifier.rs` parses the new layout, builds the 5-element vector, and hands the triple off to `groth16-solana` for the BN254 pairing check.

## Instruction-data layout (on-chain program)

```
[0..32]     sp1_vkey_hash         32 B
[32..36]    proof_len (u32 BE)     4 B
[36..36+p]  proof                  p B (356 for v6)
[36+p..]    sp1_public_inputs      variable
```

## Credits

- `programs/sp1-verify-spike/src/utils.rs` vendors proof + verifying-key parsing from [`succinctlabs/sp1-solana`](https://github.com/succinctlabs/sp1-solana) (MIT). Vendored rather than imported because the upstream hasn't released v6 support yet — see [succinctlabs/sp1-solana#23](https://github.com/succinctlabs/sp1-solana/issues/23).
- BN254 pairing arithmetic by Light Protocol's [`groth16-solana`](https://github.com/Lightprotocol/groth16-solana) (via Solana's `alt_bn128_*` syscalls).

## Status

- [x] Host verifier works against a real SP1 v6 fixture.
- [x] Solana program builds, deploys, and verifies on-chain.
- [x] Compute units and transaction size measured under real-validator conditions.
- [x] Multi-parachain-header capacity measured: up to 6 headers fit in a single tx; buffer-account pattern only needed beyond that.
- [ ] Mainnet deployment.
