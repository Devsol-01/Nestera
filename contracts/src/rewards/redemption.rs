//! Points redemption functionality for protocol benefits.

use crate::errors::SavingsError;
use crate::rewards::events::emit_points_redeemed;
use crate::rewards::storage::{get_user_rewards, save_user_rewards};
use soroban_sdk::{Address, Env};

/// Redeem points for protocol benefits (fee discounts, boost multiplier, etc.)
///
/// # Arguments
/// * `env` - Contract environment
/// * `user` - User address redeeming points
/// * `amount` - Amount of points to redeem
///
/// # Returns
/// * `Ok(())` if redemption successful
/// * `Err(SavingsError)` if insufficient points or arithmetic error
///
/// # Safety
/// * Validates user has sufficient points
/// * Uses checked arithmetic to prevent underflow
/// * Emits PointsRedeemed event on success
pub fn redeem_points(env: &Env, user: Address, amount: u128) -> Result<(), SavingsError> {
    // Validate amount
    if amount == 0 {
        return Err(SavingsError::InvalidAmount);
    }

    // Get user rewards
    let mut rewards = get_user_rewards(env, user.clone());

    // Validate sufficient balance
    if rewards.total_points < amount {
        return Err(SavingsError::InsufficientBalance);
    }

    // Deduct points safely
    rewards.total_points = rewards
        .total_points
        .checked_sub(amount)
        .ok_or(SavingsError::Overflow)?;

    // Save updated state
    save_user_rewards(env, user.clone(), &rewards);

    // Emit redemption event
    emit_points_redeemed(env, user, amount);

    Ok(())
}
