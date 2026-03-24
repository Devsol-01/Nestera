pub mod types;

use crate::errors::SavingsError;
use crate::storage_types::DataKey;
use soroban_sdk::{symbol_short, Address, Env};
use types::{AllocationConfig, Treasury};

// ========== Treasury Storage Helpers ==========

/// Retrieves the Treasury struct from persistent storage.
pub fn get_treasury(env: &Env) -> Treasury {
    env.storage()
        .persistent()
        .get(&DataKey::Treasury)
        .unwrap_or(Treasury::new())
}

/// Saves the Treasury struct to persistent storage.
fn set_treasury(env: &Env, treasury: &Treasury) {
    env.storage().persistent().set(&DataKey::Treasury, treasury);
}

// ========== Treasury Initialization ==========

/// Initializes the treasury with default zero values.
/// Called during `initialize_config`.
pub fn initialize_treasury(env: &Env) {
    let treasury = Treasury::new();
    set_treasury(env, &treasury);
}

// ========== Fee Recording ==========

/// Records a collected fee into the treasury and emits a FeeCollected event.
///
/// # Arguments
/// * `env` - The contract environment
/// * `amount` - The fee amount collected
/// * `fee_type` - A short symbol describing the fee type (e.g., "dep", "wth", "perf")
pub fn record_fee(env: &Env, amount: i128, fee_type: soroban_sdk::Symbol) {
    if amount <= 0 {
        return;
    }
    let mut treasury = get_treasury(env);
    treasury.total_fees_collected = treasury
        .total_fees_collected
        .checked_add(amount)
        .unwrap_or(treasury.total_fees_collected);
    treasury.treasury_balance = treasury
        .treasury_balance
        .checked_add(amount)
        .unwrap_or(treasury.treasury_balance);
    set_treasury(env, &treasury);

    env.events()
        .publish((symbol_short!("fee_col"), fee_type), amount);
}

/// Records yield earned into the treasury.
pub fn record_yield(env: &Env, amount: i128) {
    if amount <= 0 {
        return;
    }
    let mut treasury = get_treasury(env);
    treasury.total_yield_earned = treasury
        .total_yield_earned
        .checked_add(amount)
        .unwrap_or(treasury.total_yield_earned);
    set_treasury(env, &treasury);
}

// ========== Allocation Logic ==========

/// Allocates the unallocated treasury balance into reserves, rewards, and operations.
///
/// The allocation percentages are provided as basis points (e.g., 4000 = 40%).
/// They MUST sum to exactly 10_000 (100%).
///
/// # Arguments
/// * `env` - The contract environment
/// * `admin` - The admin address (must match the stored admin)
/// * `reserve_percent` - Reserve allocation in basis points
/// * `rewards_percent` - Rewards allocation in basis points
/// * `operations_percent` - Operations allocation in basis points
///
/// # Errors
/// * `SavingsError::Unauthorized` - If caller is not admin
/// * `SavingsError::InvalidAmount` - If percentages don't sum to 10_000
pub fn allocate_treasury(
    env: &Env,
    admin: &Address,
    reserve_percent: u32,
    rewards_percent: u32,
    operations_percent: u32,
) -> Result<Treasury, SavingsError> {
    // Verify admin
    let stored_admin: Address = env
        .storage()
        .instance()
        .get(&DataKey::Admin)
        .ok_or(SavingsError::Unauthorized)?;
    if stored_admin != *admin {
        return Err(SavingsError::Unauthorized);
    }
    admin.require_auth();

    // Validate percentages sum to 100%
    let total = reserve_percent
        .checked_add(rewards_percent)
        .and_then(|s| s.checked_add(operations_percent))
        .ok_or(SavingsError::Overflow)?;

    if total != 10_000 {
        return Err(SavingsError::InvalidAmount);
    }

    let mut treasury = get_treasury(env);
    let available = treasury.treasury_balance;

    if available <= 0 {
        return Ok(treasury);
    }

    // Calculate splits
    let reserve_amount = available
        .checked_mul(reserve_percent as i128)
        .ok_or(SavingsError::Overflow)?
        / 10_000;
    let rewards_amount = available
        .checked_mul(rewards_percent as i128)
        .ok_or(SavingsError::Overflow)?
        / 10_000;
    // Operations gets the remainder to avoid rounding dust
    let operations_amount = available
        .checked_sub(reserve_amount)
        .and_then(|v| v.checked_sub(rewards_amount))
        .ok_or(SavingsError::Underflow)?;

    // Update balances
    treasury.reserve_balance = treasury
        .reserve_balance
        .checked_add(reserve_amount)
        .ok_or(SavingsError::Overflow)?;
    treasury.rewards_balance = treasury
        .rewards_balance
        .checked_add(rewards_amount)
        .ok_or(SavingsError::Overflow)?;
    treasury.operations_balance = treasury
        .operations_balance
        .checked_add(operations_amount)
        .ok_or(SavingsError::Overflow)?;

    // Zero out the unallocated balance
    treasury.treasury_balance = 0;

    // Store the allocation config for reference
    let alloc_config = AllocationConfig {
        reserve_percent,
        rewards_percent,
        operations_percent,
    };
    env.storage()
        .persistent()
        .set(&DataKey::AllocationConfig, &alloc_config);

    set_treasury(env, &treasury);

    env.events().publish(
        (symbol_short!("alloc"),),
        (reserve_amount, rewards_amount, operations_amount),
    );

    Ok(treasury)
}
