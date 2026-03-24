use crate::governance;
use crate::storage_types::DataKey;
use crate::SavingsError;
use soroban_sdk::{Address, Env};

// --- Admin Setters (with governance transition) ---

pub fn set_flexi_rate(env: &Env, caller: Address, rate: i128) -> Result<(), SavingsError> {
    caller.require_auth();
    governance::validate_admin_or_governance(env, &caller)?;

    if rate < 0 {
        return Err(SavingsError::InvalidInterestRate);
    }
    env.storage().instance().set(&DataKey::FlexiRate, &rate);
    Ok(())
}

pub fn set_goal_rate(env: &Env, caller: Address, rate: i128) -> Result<(), SavingsError> {
    caller.require_auth();
    governance::validate_admin_or_governance(env, &caller)?;

    if rate < 0 {
        return Err(SavingsError::InvalidInterestRate);
    }
    env.storage().instance().set(&DataKey::GoalRate, &rate);
    Ok(())
}

pub fn set_group_rate(env: &Env, caller: Address, rate: i128) -> Result<(), SavingsError> {
    caller.require_auth();
    governance::validate_admin_or_governance(env, &caller)?;

    if rate < 0 {
        return Err(SavingsError::InvalidInterestRate);
    }
    env.storage().instance().set(&DataKey::GroupRate, &rate);
    Ok(())
}

pub fn set_lock_rate(
    env: &Env,
    caller: Address,
    duration_days: u64,
    rate: i128,
) -> Result<(), SavingsError> {
    caller.require_auth();
    governance::validate_admin_or_governance(env, &caller)?;

    if rate < 0 {
        return Err(SavingsError::InvalidInterestRate);
    }
    env.storage()
        .instance()
        .set(&DataKey::LockRate(duration_days), &rate);
    Ok(())
}

// --- Getters ---

pub fn get_flexi_rate(env: &Env) -> i128 {
    env.storage()
        .instance()
        .get(&DataKey::FlexiRate)
        .unwrap_or(0)
}

pub fn get_goal_rate(env: &Env) -> i128 {
    env.storage()
        .instance()
        .get(&DataKey::GoalRate)
        .unwrap_or(0)
}

pub fn get_group_rate(env: &Env) -> i128 {
    env.storage()
        .instance()
        .get(&DataKey::GroupRate)
        .unwrap_or(0)
}

pub fn get_lock_rate(env: &Env, duration_days: u64) -> Result<i128, SavingsError> {
    env.storage()
        .instance()
        .get(&DataKey::LockRate(duration_days))
        .ok_or(SavingsError::PlanNotFound)
}

// --- Interest Calculation Helpers ---

pub fn calculate_flexi_interest(balance: i128, rate: i128, duration_seconds: u64) -> i128 {
    if balance <= 0 || rate <= 0 {
        return 0;
    }
    // Simple Interest: (balance * rate * time) / (10000 * 365 * 24 * 60 * 60)
    // Assuming rate is in basis points (e.g. 500 = 5.00%)
    // 10000 is for basis points
    // Time is in seconds, so we divide by seconds in a year (~31536000)

    // Using i128 for precision and to match input types
    let numerator = balance
        .checked_mul(rate)
        .unwrap_or(0)
        .checked_mul(duration_seconds as i128)
        .unwrap_or(0);

    let denominator = 10000i128 * 365 * 24 * 60 * 60;

    numerator / denominator
}

pub fn calculate_lock_interest(amount: i128, rate: i128) -> i128 {
    if amount <= 0 || rate <= 0 {
        return 0;
    }
    // For fixed lock, maybe it's (amount * rate) / 10000?
    // Or is it annualized?
    // "LockRate maps duration -> interest rate" usually implies a fixed yield for that duration or annualized.
    // If it's APY, we need duration.
    // However, if the rate is SPECIFIC to that lock duration tier (e.g. "5% for 30 days"), then it might be flat.
    // BUT usually rates are APY.
    // Let's assume simplest interpretation:
    // The instructions say "LockRate => maps lock duration to interest rate".
    // If I lock for 30 days, I get X rate.
    // Let's assume the rate provided IS the return for that period for now, OR APY.
    // Given 'calculate_flexi' has duration, but 'calculate_lock_interest' signature in prompt was:
    // `calculate_lock_interest(amount: i128, rate: i128) -> i128`
    // It DOES NOT take duration. This implies the 'rate' passed in is already the *effective* rate for the period check,
    // OR it calculates a flat amount based on the rate (like a fixed % return).
    // Let's go with: Result = (Amount * Rate) / 10000.

    amount.checked_mul(rate).unwrap_or(0) / 10000
}
