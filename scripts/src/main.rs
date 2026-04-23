use alloy_primitives::{FixedBytes, U256};
use alloy_sol_types::{SolValue, sol};
use parity_scale_codec::{Decode, Encode};
use sha3::{Digest, Keccak256};

use sp1_verify_spike::{SP1Groth16Proof, process_instruction};

use solana_program_test::{ProgramTest, processor};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signer::Signer,
    transaction::Transaction,
};

// Fixtures copied verbatim from
// modules/pallets/beefy-consensus-proofs/src/benchmarking.rs:37,39
const TRUSTED_STATE_SCALE_HEX: &str = "2279d60118532a010000000000000000000000000000000000000000000000000000000000000000751200000000000057020000a7161e52f2f4249039441385a41c6c8e36207a9b6a65d9bfae4272156ec31f49751200000000000057020000a7161e52f2f4249039441385a41c6c8e36207a9b6a65d9bfae4272156ec31f49";

const WIRE_PROOF_HEX: &str = "012a79d6017512000000000000002979d601e1dbc67b9da4b90227fb3dc2e7ffdce4e120d583502399e4bd083c02651ca5eb761200000000000057020000a7161e52f2f4249039441385a41c6c8e36207a9b6a65d9bfae4272156ec31f4963bc2eb07f9c83afe64eb8815b626cd0a7d2a1bbb4630a44a1896af297d0135d04e504739e9bd7f1addf87db9b6a762bd0e1713baa895c3b82b4595080e5ba02fb5b3cf2915702b49122c32b822e6a11384074d8902d5ea5f79c7cb0d7804e49501b8b532298f49e38d3f7140ce1ba61c243152e4e380b37eb628e08d5270d8b2c5e4ebedd84bb14066175726120fbc4d208000000000452505352902a869d4e00b3bb93f1e88e41a2b5f51fc637626b4ce1da15749ef2d79de4797a9ae459070449534d50010118a13886ac93d163a1d22cdef94e018eba5189424a66b7bd03a5ac232beb46bf08b0f9d2b979fff833d7e21a64a5183c61e2630c0b452236baba3c1b4ff41821044953544d20ca3be169000000000561757261010152d45dea4dcf058b0610e12981e0e4c97ad153f26481510c0b78beedf1848b4dd2abd37b8c6b800b72fa12199898eca7651471b49e38d6167a84fb6e2df7c78400000000270d000091054388a21c0000000000000000000000000000000000000000000000000000000000000000002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f2535200000000000000000000000000000000000000000000000000000000000000002ac5e596c552ee76353c176f0870e47a0aa765ceafc4c65b03dbf434e27fa9062f185bdc40f7aae982c1c8c6b766dd491a1e1cd60128efbc58da965e5be96320287f4ce1b04538f0c8287c8eff096c36df67dc17970032546c9b3d4dd5510c5c25e880e13469e1e1aca1b41c367f2ecf04da65f7602fb53ec212b03d0148157b2cd9a79a9779f350d240e6d4c980848302fca8c7447c5fa7ac8d3c6eefcd0c640acff8b27ea316db978652553e3d054765094cf0dab6085a616489cdb973c42b258e22f346ac3ceb3e2e6750c37dad1f98f6ca15d1f70659343caa52dbbcad150b75dd2dcf0ba0a664ea4605b291df54ab1aa5b4c55034b9425ba29cc87eca7b";

const PROOF_TYPE_SP1: u8 = 0x01;

// Local SCALE-layout-compatible replicas of the types from
// modules/consensus/beefy/primitives and sp_consensus_beefy.
// Field order and byte layout must match exactly.

#[derive(Clone, Encode, Decode)]
struct MmrLeafVersion(u8);

#[derive(Clone, Encode, Decode)]
struct BeefyAuthoritySet {
    id: u64,
    len: u32,
    keyset_commitment: [u8; 32],
}

#[derive(Clone, Encode, Decode)]
struct MmrLeaf {
    version: MmrLeafVersion,
    parent_number_and_hash: (u32, [u8; 32]),
    beefy_next_authority_set: BeefyAuthoritySet,
    leaf_extra: [u8; 32],
}

#[derive(Clone, Encode, Decode)]
struct ParachainHeader {
    header: Vec<u8>,
    index: u32,
    para_id: u32,
}

#[derive(Clone, Encode, Decode)]
struct Sp1BeefyProof {
    block_number: u32,
    validator_set_id: u64,
    mmr_leaf: MmrLeaf,
    headers: Vec<ParachainHeader>,
    proof: Vec<u8>,
}

#[derive(Clone, Encode, Decode)]
struct ConsensusState {
    latest_beefy_height: u32,
    beefy_activation_block: u32,
    mmr_root_hash: [u8; 32],
    current_authorities: BeefyAuthoritySet,
    next_authorities: BeefyAuthoritySet,
}

// Mirrors modules/consensus/beefy/verifier/src/sp1.rs:30-42
sol! {
    struct ParachainHeaderHash {
        uint256 id;
        bytes32 hash;
    }
    struct PublicInputs {
        bytes32 authorities_root;
        uint256 authorities_len;
        bytes32 leaf_hash;
        ParachainHeaderHash[] headers;
    }
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(bytes);
    h.finalize().into()
}

fn build_public_inputs(trusted: &ConsensusState, proof: &Sp1BeefyProof) -> Vec<u8> {
    let authority = if proof.validator_set_id == trusted.next_authorities.id {
        &trusted.next_authorities
    } else if proof.validator_set_id == trusted.current_authorities.id {
        &trusted.current_authorities
    } else {
        panic!("validator_set_id matches neither current nor next authorities");
    };

    let headers: Vec<ParachainHeaderHash> = proof
        .headers
        .iter()
        .map(|h| ParachainHeaderHash {
            id: U256::from(h.para_id),
            hash: FixedBytes::from(keccak256(&h.header)),
        })
        .collect();

    let pi = PublicInputs {
        authorities_root: FixedBytes::from(authority.keyset_commitment),
        authorities_len: U256::from(authority.len),
        leaf_hash: FixedBytes::from(keccak256(&proof.mmr_leaf.encode())),
        headers,
    };
    pi.abi_encode()
}

#[tokio::main]
async fn main() {
    let trusted_bytes = hex::decode(TRUSTED_STATE_SCALE_HEX).expect("valid hex");
    let wire_bytes = hex::decode(WIRE_PROOF_HEX).expect("valid hex");

    assert_eq!(wire_bytes[0], PROOF_TYPE_SP1, "unexpected proof type prefix");
    let proof_scale = &wire_bytes[1..];

    let trusted = ConsensusState::decode(&mut &trusted_bytes[..]).expect("decode trusted state");
    let sp1_proof = Sp1BeefyProof::decode(&mut &proof_scale[..]).expect("decode sp1 beefy proof");

    let public_inputs = build_public_inputs(&trusted, &sp1_proof);

    println!("wire proof bytes:       {}", wire_bytes.len());
    println!("inner groth16 proof:    {}", sp1_proof.proof.len());
    println!("public inputs:          {}", public_inputs.len());
    println!("parachain headers:      {}", sp1_proof.headers.len());
    if let Some(h) = sp1_proof.headers.first() {
        println!("first parachain header: {} bytes, para_id {}", h.header.len(), h.para_id);
    }

    let program_instruction_data = SP1Groth16Proof {
        proof: sp1_proof.proof.clone(),
        sp1_public_inputs: public_inputs,
    };

    let program_id = Pubkey::new_unique();
    let (banks_client, payer, recent_blockhash) = ProgramTest::new(
        "sp1_verify_spike",
        program_id,
        processor!(process_instruction),
    )
    .start()
    .await;

    let instruction = Instruction::new_with_borsh(
        program_id,
        &program_instruction_data,
        vec![AccountMeta::new(payer.pubkey(), false)],
    );

    let mut transaction = Transaction::new_with_payer(&[instruction], Some(&payer.pubkey()));
    transaction.sign(&[&payer], recent_blockhash);

    banks_client
        .process_transaction(transaction)
        .await
        .expect("verify_sp1 instruction failed");

    println!("beefy groth16 verification ok");
}
