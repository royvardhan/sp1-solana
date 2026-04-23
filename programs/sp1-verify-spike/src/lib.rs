use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, msg, program_error::ProgramError,
    pubkey::Pubkey,
};
use sp1_solana::verify_proof;

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

const BEEFY_VKEY_HASH: &str =
    "0x0059fd0bff44da77999bb7974cbcf2ac7dc89e5869352f20a2f3cd46c9f53d5c";

#[derive(BorshDeserialize, BorshSerialize)]
pub struct SP1Groth16Proof {
    pub proof: Vec<u8>,
    pub sp1_public_inputs: Vec<u8>,
}

pub fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let groth16_proof = SP1Groth16Proof::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    let vk = sp1_solana::GROTH16_VK_5_0_0_BYTES;

    verify_proof(
        &groth16_proof.proof,
        &groth16_proof.sp1_public_inputs,
        BEEFY_VKEY_HASH,
        vk,
    )
    .map_err(|_| ProgramError::InvalidInstructionData)?;

    msg!("sp1 beefy groth16 verification ok");
    Ok(())
}
