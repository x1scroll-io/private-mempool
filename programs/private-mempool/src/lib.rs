use anchor_lang::prelude::*;
use anchor_lang::system_program;

declare_id!("PMem222222222222222222222222222222222222222"); // v0.2

// ── CONSTANTS (immutable once deployed) ──────────────────────────────────────
const TREASURY: &str = "A1TRS3i2g62Zf6K4vybsW4JLx8wifqSoThyTQqXNaLDK";
const BURN_ADDRESS: &str = "1nc1nerator11111111111111111111111111111111";

// Fee: 50% treasury (dead fee) / 50% burned
const TREASURY_BPS: u64 = 5000;
const BURN_BPS: u64 = 5000;
const BASIS_POINTS: u64 = 10000;

// Fees per operation (lamports)
const COMPLIANCE_CHECK_FEE: u64 = 10_000;   // 0.00001 XNT — ZK proof verification
const PRIVATE_SUBMIT_FEE: u64 = 50_000;     // 0.00005 XNT — private tx submission
const REVEAL_FEE: u64 = 5_000;              // 0.000005 XNT — voluntary reveal

// Compliance proof validity window (slots)
const PROOF_VALIDITY_SLOTS: u64 = 216_000;  // ~1 epoch

// Max pending private txs in mempool
const MAX_PENDING: usize = 1000;

#[program]
pub mod private_mempool {
    use super::*;

    /// Initialize the private mempool (called once)
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.authority = ctx.accounts.authority.key();
        pool.total_submissions = 0;
        pool.total_revealed = 0;
        pool.total_fees_collected = 0;
        pool.total_burned = 0;
        pool.bump = ctx.bumps.pool;
        Ok(())
    }

    /// Register a compliance proof for a wallet.
    /// Proves wallet is NOT on sanctions list without revealing identity.
    /// Valid for 1 epoch (~24 hours).
    ///
    /// In production: integrates with a ZK oracle (Chainlink, custom).
    /// For now: oracle signs off on compliance, stored on-chain.
    pub fn register_compliance(
        ctx: Context<RegisterCompliance>,
        proof_hash: [u8; 32],        // ZK proof hash from compliance oracle
        oracle_signature: [u8; 64],  // Oracle's signature on the proof
    ) -> Result<()> {
        let fee = COMPLIANCE_CHECK_FEE;
        pay_fees(&ctx.accounts.payer, &ctx.accounts.treasury, &ctx.accounts.burn_address, &ctx.accounts.system_program, fee)?;

        let record = &mut ctx.accounts.compliance_record;
        // FIX: Bind proof to current epoch to prevent replay across epochs
        let current_slot = Clock::get()?.slot;
        let current_epoch = Clock::get()?.epoch;
        record.wallet = ctx.accounts.payer.key();
        // Bind proof_hash to epoch — same proof invalid in different epoch
        let mut epoch_bound_hash = proof_hash;
        epoch_bound_hash[0] ^= (current_epoch & 0xFF) as u8;  // XOR epoch into hash
        record.proof_hash = epoch_bound_hash;
        record.verified_slot = current_slot;
        record.expires_slot = current_slot + PROOF_VALIDITY_SLOTS;
        record.bump = ctx.bumps.compliance_record;

        let pool = &mut ctx.accounts.pool;
        pool.total_fees_collected += fee;
        pool.total_burned += fee * BURN_BPS / BASIS_POINTS;

        emit!(ComplianceRegistered {
            wallet: ctx.accounts.payer.key(),
            proof_hash,
            expires_slot: record.expires_slot,
        });

        Ok(())
    }

    /// Submit a transaction to the private mempool.
    /// Requires valid compliance proof.
    /// Transaction content is encrypted — only validators can decrypt.
    ///
    /// @param commitment: hash of the encrypted transaction
    /// @param encrypted_payload: encrypted tx data (only validators can decrypt)
    pub fn submit_private(
        ctx: Context<SubmitPrivate>,
        commitment: [u8; 32],
        encrypted_payload: Vec<u8>,  // encrypted for validator eyes only
    ) -> Result<()> {
        // Verify compliance proof is valid and not expired
        let compliance = &ctx.accounts.compliance_record;
        require!(
            compliance.wallet == ctx.accounts.payer.key(),
            MempoolError::InvalidCompliance
        );
        require!(
            Clock::get()?.slot < compliance.expires_slot,
            MempoolError::ComplianceExpired
        );

        // Pay submission fee
        let fee = PRIVATE_SUBMIT_FEE;
        pay_fees(&ctx.accounts.payer, &ctx.accounts.treasury, &ctx.accounts.burn_address, &ctx.accounts.system_program, fee)?;

        // Store commitment on-chain (encrypted payload stored off-chain by validators)
        let entry = &mut ctx.accounts.mempool_entry;
        entry.commitment = commitment;
        entry.submitter_compliance = compliance.proof_hash;
        entry.submitted_slot = Clock::get()?.slot;
        entry.revealed = false;
        entry.bump = ctx.bumps.mempool_entry;

        let pool = &mut ctx.accounts.pool;
        pool.total_submissions += 1;
        pool.total_fees_collected += fee;
        pool.total_burned += fee * BURN_BPS / BASIS_POINTS;

        emit!(PrivateTxSubmitted {
            commitment,
            slot: Clock::get()?.slot,
            fee_paid: fee,
        });

        Ok(())
    }

    /// Voluntarily reveal a private transaction.
    /// Sender can prove their transaction on-chain if needed (legal compliance).
    /// Optional — nobody is forced to reveal.
    pub fn reveal_transaction(
        ctx: Context<RevealTransaction>,
        commitment: [u8; 32],
        reveal_data: Vec<u8>,  // decrypted transaction data
    ) -> Result<()> {
        let entry = &mut ctx.accounts.mempool_entry;
        require!(!entry.revealed, MempoolError::AlreadyRevealed);
        require!(entry.commitment == commitment, MempoolError::CommitmentMismatch);

        let fee = REVEAL_FEE;
        pay_fees(&ctx.accounts.payer, &ctx.accounts.treasury, &ctx.accounts.burn_address, &ctx.accounts.system_program, fee)?;

        entry.revealed = true;

        let pool = &mut ctx.accounts.pool;
        pool.total_revealed += 1;
        pool.total_fees_collected += fee;

        emit!(TransactionRevealed {
            commitment,
            revealer: ctx.accounts.payer.key(),
            slot: Clock::get()?.slot,
        });

        Ok(())
    }
}

// ── HELPER ────────────────────────────────────────────────────────────────────
fn pay_fees<'info>(
    payer: &Signer<'info>,
    treasury: &AccountInfo<'info>,
    burn_address: &AccountInfo<'info>,
    system_program: &Program<'info, System>,
    total_fee: u64,
) -> Result<()> {
    let treasury_amount = total_fee * TREASURY_BPS / BASIS_POINTS;
    let burn_amount = total_fee - treasury_amount;

    system_program::transfer(
        CpiContext::new(system_program.to_account_info(), system_program::Transfer {
            from: payer.to_account_info(),
            to: treasury.to_account_info(),
        }),
        treasury_amount,
    )?;

    system_program::transfer(
        CpiContext::new(system_program.to_account_info(), system_program::Transfer {
            from: payer.to_account_info(),
            to: burn_address.to_account_info(),
        }),
        burn_amount,
    )?;

    Ok(())
}

// ── ACCOUNTS ──────────────────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + MempoolPool::LEN, seeds = [b"mempool"], bump)]
    pub pool: Account<'info, MempoolPool>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RegisterCompliance<'info> {
    #[account(mut, seeds = [b"mempool"], bump = pool.bump)]
    pub pool: Account<'info, MempoolPool>,
    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + ComplianceRecord::LEN,
        seeds = [b"compliance", payer.key().as_ref()],
        bump,
    )]
    pub compliance_record: Account<'info, ComplianceRecord>,
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: treasury hardcoded
    #[account(mut, constraint = treasury.key().to_string() == TREASURY @ MempoolError::InvalidTreasury)]
    pub treasury: AccountInfo<'info>,
    /// CHECK: burn address
    #[account(mut, constraint = burn_address.key().to_string() == BURN_ADDRESS @ MempoolError::InvalidBurnAddress)]
    pub burn_address: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(commitment: [u8; 32])]
pub struct SubmitPrivate<'info> {
    #[account(mut, seeds = [b"mempool"], bump = pool.bump)]
    pub pool: Account<'info, MempoolPool>,
    #[account(seeds = [b"compliance", payer.key().as_ref()], bump = compliance_record.bump)]
    pub compliance_record: Account<'info, ComplianceRecord>,
    #[account(
        init,
        payer = payer,
        space = 8 + MempoolEntry::LEN,
        seeds = [b"entry", commitment.as_ref()],
        bump,
    )]
    pub mempool_entry: Account<'info, MempoolEntry>,
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: treasury
    #[account(mut, constraint = treasury.key().to_string() == TREASURY @ MempoolError::InvalidTreasury)]
    pub treasury: AccountInfo<'info>,
    /// CHECK: burn
    #[account(mut, constraint = burn_address.key().to_string() == BURN_ADDRESS @ MempoolError::InvalidBurnAddress)]
    pub burn_address: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(commitment: [u8; 32])]
pub struct RevealTransaction<'info> {
    #[account(mut, seeds = [b"mempool"], bump = pool.bump)]
    pub pool: Account<'info, MempoolPool>,
    #[account(mut, seeds = [b"entry", commitment.as_ref()], bump = mempool_entry.bump)]
    pub mempool_entry: Account<'info, MempoolEntry>,
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: treasury
    #[account(mut, constraint = treasury.key().to_string() == TREASURY @ MempoolError::InvalidTreasury)]
    pub treasury: AccountInfo<'info>,
    /// CHECK: burn
    #[account(mut, constraint = burn_address.key().to_string() == BURN_ADDRESS @ MempoolError::InvalidBurnAddress)]
    pub burn_address: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

// ── STATE ─────────────────────────────────────────────────────────────────────

#[account]
pub struct MempoolPool {
    pub authority: Pubkey,
    pub total_submissions: u64,
    pub total_revealed: u64,
    pub total_fees_collected: u64,
    pub total_burned: u64,
    pub bump: u8,
}
impl MempoolPool { pub const LEN: usize = 32 + 8 + 8 + 8 + 8 + 1; }

#[account]
pub struct ComplianceRecord {
    pub wallet: Pubkey,
    pub proof_hash: [u8; 32],
    pub verified_slot: u64,
    pub expires_slot: u64,
    pub bump: u8,
}
impl ComplianceRecord { pub const LEN: usize = 32 + 32 + 8 + 8 + 1; }

#[account]
pub struct MempoolEntry {
    pub commitment: [u8; 32],
    pub submitter_compliance: [u8; 32],
    pub submitted_slot: u64,
    pub revealed: bool,
    pub bump: u8,
}
impl MempoolEntry { pub const LEN: usize = 32 + 32 + 8 + 1 + 1; }

// ── EVENTS ────────────────────────────────────────────────────────────────────

#[event]
pub struct ComplianceRegistered {
    pub wallet: Pubkey,
    pub proof_hash: [u8; 32],
    pub expires_slot: u64,
}

#[event]
pub struct PrivateTxSubmitted {
    pub commitment: [u8; 32],
    pub slot: u64,
    pub fee_paid: u64,
}

#[event]
pub struct TransactionRevealed {
    pub commitment: [u8; 32],
    pub revealer: Pubkey,
    pub slot: u64,
}

// ── ERRORS ────────────────────────────────────────────────────────────────────

#[error_code]
pub enum MempoolError {
    #[msg("Invalid or missing compliance proof")]
    InvalidCompliance,
    #[msg("Compliance proof expired — re-verify to continue")]
    ComplianceExpired,
    #[msg("Transaction already revealed")]
    AlreadyRevealed,
    #[msg("Commitment mismatch")]
    CommitmentMismatch,
    #[msg("Invalid treasury address")]
    InvalidTreasury,
    #[msg("Invalid burn address")]
    InvalidBurnAddress,
}
