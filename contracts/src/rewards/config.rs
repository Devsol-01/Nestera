use super::storage_types::{RewardsConfig, RewardsDataKey};
use crate::errors::SavingsError;
use soroban_sdk::{Address, Env};

/// Initializes the global rewards configuration.
pub fn initialize_rewards_config(env: &Env, config: RewardsConfig) -> Result<(), SavingsError> {
    if env.storage().instance().has(&RewardsDataKey::Config) {
        return Err(SavingsError::ConfigAlreadyInitialized);
    }

    validate_config(&config)?;
    env.storage()
        .instance()
        .set(&RewardsDataKey::Config, &config);
    Ok(())
}

/// Updates existing rewards configuration. Only accessible by Admin.
pub fn update_rewards_config(
    env: &Env,
    admin: Address,
    config: RewardsConfig,
) -> Result<(), SavingsError> {
    // 1. Ensure the transaction was signed by the address provided
    admin.require_auth();

    // 2. Security: Verify this address is actually the authorized Admin
    // For now, we'll check against the admin address stored in your contract state.
    // Replace 'get_admin(env)' with whatever function you use to fetch your admin address.
    let stored_admin: Address = env
        .storage()
        .instance()
        .get(&soroban_sdk::symbol_short!("admin"))
        .ok_or(SavingsError::Unauthorized)?;

    if admin != stored_admin {
        return Err(SavingsError::Unauthorized);
    }

    // 3. Validate and Save
    validate_config(&config)?;
    env.storage()
        .instance()
        .set(&RewardsDataKey::Config, &config);
    Ok(())
}

/// Fetches the current rewards configuration.
pub fn get_rewards_config(env: &Env) -> Result<RewardsConfig, SavingsError> {
    env.storage()
        .instance()
        .get(&RewardsDataKey::Config)
        .ok_or(SavingsError::InternalError) // Consider adding ConfigNotInitialized to errors.rs
}

/// Validates that bonus rates are within 0-100% (0-10000 BPS).
fn validate_config(config: &RewardsConfig) -> Result<(), SavingsError> {
    if config.streak_bonus_bps > 10_000 || config.long_lock_bonus_bps > 10_000 {
        return Err(SavingsError::InvalidFeeBps);
    }

    // Validate anti-farming parameters
    if config.max_streak_multiplier > 10_000 {
        return Err(SavingsError::InvalidFeeBps);
    }

    if config.min_deposit_for_rewards < 0 {
        return Err(SavingsError::InvalidAmount);
    }

    Ok(())
}
