//! SP1 v6 Groth16 verification on Solana — direct integration with Light
//! Protocol's `groth16-solana`. No dependency on `succinctlabs/sp1-solana`.
//!
//! Phase 2B.1: library surface + a minimal on-chain entrypoint that wires the
//! verifier into a deployable program. Instruction data layout below is the
//! simplest possible — Phase 2B.2 will replace it with an account-based flow
//! once the payload exceeds the 1232-byte tx cap.

pub mod types;
pub mod utils;
pub mod verifier;
pub mod vk;

pub use types::{ConsensusState, PROOF_TYPE_SP1, Sp1BeefyProof};
pub use verifier::{extract_vk_root, verify_sp1_v6};
pub use vk::{GROTH16_VK_V6_1_0_BYTES, VK_ROOT_V6_1_0_BYTES};

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint {
    use solana_program::{
        account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, msg,
        program_error::ProgramError, pubkey::Pubkey,
    };

    use crate::{VK_ROOT_V6_1_0_BYTES, verify_sp1_v6};

    entrypoint!(process_instruction);

    /// Instruction data layout (big-endian, fixed offsets):
    ///   [0..32]    sp1_vkey_hash       — 32 B
    ///   [32..36]   proof_len           — u32 big-endian
    ///   [36..36+p] proof               — SP1 v6 Groth16 proof (exactly 356 B)
    ///   [rest]     sp1_public_inputs   — Solidity-ABI-encoded BEEFY PublicInputs
    fn process_instruction(
        _program_id: &Pubkey,
        _accounts: &[AccountInfo],
        data: &[u8],
    ) -> ProgramResult {
        if data.len() < 36 {
            return Err(ProgramError::InvalidInstructionData);
        }

        let mut sp1_vkey_hash = [0u8; 32];
        sp1_vkey_hash.copy_from_slice(&data[0..32]);

        let proof_len =
            u32::from_be_bytes([data[32], data[33], data[34], data[35]]) as usize;

        if data.len() < 36 + proof_len {
            return Err(ProgramError::InvalidInstructionData);
        }

        let proof = &data[36..36 + proof_len];
        let public_inputs = &data[36 + proof_len..];

        verify_sp1_v6(
            proof,
            public_inputs,
            &sp1_vkey_hash,
            &VK_ROOT_V6_1_0_BYTES,
            &[0u8; 32],
        )
        .map_err(|_| ProgramError::InvalidInstructionData)?;

        msg!("sp1 v6 beefy groth16 verification ok");
        Ok(())
    }
}
