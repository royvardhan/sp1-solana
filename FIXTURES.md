# Fixtures

Every piece of test data the verifier and its harnesses consume, in one place.

## Files in `proofs/`

| File | Size | What it is |
|---|---|---|
| `groth16_vk_v6_1_0.bin` | 492 B | The Groth16 verifying key for SP1 v6.1.0. Byte-identical to upstream [`succinctlabs/sp1@v6.1.0/crates/verifier/vk-artifacts/groth16_vk.bin`](https://github.com/succinctlabs/sp1/blob/v6.1.0/crates/verifier/vk-artifacts/groth16_vk.bin) (sha256 `4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696`). Loaded via `include_bytes!` in `programs/sp1-verify-spike/src/vk.rs`. |
| `naive_consensus_message.bin` | 33,985 B | Historical artifact from an abandoned exploration of non-zk BEEFY verification. Generated from live Polkadot RPC. Not used by the SP1 adapter — kept only as reference data. |
| `naive_trusted_state.bin` | 128 B | Same — historical. |

## Inlined constants

Defined as hex literals in `scripts/src/main.rs` and `scripts/src/onchain_tx.rs`. Copied once from Hyperbridge's [`benchmarking.rs`](https://github.com/polytope-labs/hyperbridge/blob/main/modules/pallets/beefy-consensus-proofs/src/benchmarking.rs) so the spike can run without a live network connection.

| Constant | Size | What it is |
|---|---|---|
| `WIRE_PROOF_HEX` | 808 B | A real Hyperbridge BEEFY consensus update for one relay-chain block. Format: `[0x01] ++ SCALE-encoded Sp1BeefyProof`. The inner SP1 Groth16 proof is 356 bytes. |
| `TRUSTED_STATE_SCALE_HEX` | 128 B | The `ConsensusState` (authority set + latest verified height) that precedes `WIRE_PROOF_HEX`. Required to verify the proof. |
| `SP1_VKEY_HASH_HEX` | 32 B | Hash of the SP1 circuit that generated the proof (Hyperbridge's BEEFY verifier circuit): `0x0059fd0bff44da77999bb7974cbcf2ac7dc89e5869352f20a2f3cd46c9f53d5c`. Feeds into the Groth16 public inputs. |

## Constants in code

| Constant | Defined in | What it is |
|---|---|---|
| `VK_ROOT_V6_1_0_BYTES` | `programs/sp1-verify-spike/src/vk.rs` | `0x002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352` — the recursion-VK merkle root that SP1 v6 commits to as a public input. Upstream computes this dynamically; it's constant per SP1 version, so we captured it from the fixture once (extractable via `extract_vk_root(proof)`) and hardcoded. |

## Decoded proof structure

`Sp1BeefyProof` after SCALE decoding (see `programs/sp1-verify-spike/src/types.rs`):

```
block_number:     u32
validator_set_id: u64
mmr_leaf:         MmrLeaf
headers:          Vec<ParachainHeader>
proof:            Vec<u8>   // 356 B for SP1 v6
```

For the fixture above:

```
block_number:            30,701,354
validator_set_id:        0x1275
parachain headers:       1 (para_id 3367, 313 B SCALE-encoded)
inner Groth16 proof:     356 B
```

## Groth16 public-input construction

The BEEFY circuit commits to this Solidity-ABI-encoded struct:

```solidity
struct PublicInputs {
    bytes32 authorities_root;         // = authority.keyset_commitment
    uint256 authorities_len;          // = authority.len
    bytes32 leaf_hash;                // = keccak256(mmr_leaf.encode())
    ParachainHeaderHash[] headers;    // each = (para_id, keccak256(header_scale))
}
```

Byte-identical to the EVM verifier's public-input construction in [`sp1.rs:77-83`](https://github.com/polytope-labs/hyperbridge/blob/main/modules/consensus/beefy/verifier/src/sp1.rs#L77-L83). Encoded length is 256 bytes for this fixture (1 header). See `build_public_inputs` in either script for the implementation.

## Regenerating fixtures

The scripts under `scripts/` use the inlined hex and don't touch a live network. If you need a fresh BEEFY proof for a different block or different SP1 version:

1. Check out the [polytope-labs/hyperbridge](https://github.com/polytope-labs/hyperbridge) repo.
2. Run `dump_sp1_fixture_scale_bytes` in `modules/consensus/beefy/verifier/src/test.rs` against a node pair (relay + parachain). It prints hex strings ready to inline.
3. Replace the three `*_HEX` constants in `scripts/src/{main,onchain_tx}.rs`.

For a new SP1 version, also regenerate `proofs/groth16_vk_v6_1_0.bin` and `VK_ROOT_V6_1_0_BYTES`.
