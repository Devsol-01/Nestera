use soroban_sdk::{Address, Env};

use crate::ensure_not_paused;
use crate::errors::SavingsError;
use crate::storage_types::{DataKey, User};
use crate::ttl;

/// Check if a user exists in storage
///
/// # Arguments
/// * `env` - The contract environment
/// * `user` - The address of the user to check
///
/// # Returns
/// `true` if the user exists, `false` otherwise
pub fn user_exists(env: &Env, user: &Address) -> bool {
    let key = DataKey::User(user.clone());
    let exists = env.storage().persistent().has(&key);
    if exists {
        ttl::extend_user_ttl(env, user);
    }
    exists
}

/// Get a user from storage
///
/// # Arguments
/// * `env` - The contract environment
/// * `user` - The address of the user to retrieve
///
/// # Returns
/// `Ok(User)` if found, `Err(SavingsError::UserNotFound)` otherwise
pub fn get_user(env: &Env, user: &Address) -> Result<User, SavingsError> {
    let key = DataKey::User(user.clone());
    let user_data = env
        .storage()
        .persistent()
        .get(&key)
        .ok_or(SavingsError::UserNotFound)?;

    // Extend TTL on access
    ttl::extend_user_ttl(env, user);

    Ok(user_data)
}

/// Initialize a new user in the savings contract
///
/// This function creates a new user record with zero balances.
/// Only the user themselves can initialize their account.
///
/// # Arguments
/// * `env` - The contract environment
/// * `user` - The address of the user to initialize
///
/// # Returns
/// `Ok(())` on success, `Err(SavingsError::UserAlreadyExists)` if user already exists
///
/// # Authorization
/// Requires authorization from the user being initialized
pub fn initialize_user(env: &Env, user: Address) -> Result<(), SavingsError> {
    ensure_not_paused(env)?;
    // Require authorization from the user being initialized
    user.require_auth();

    // Check if user already exists
    if user_exists(env, &user) {
        return Err(SavingsError::UserAlreadyExists);
    }

    // Create new user with default values
    let new_user = User::new();

    // Store user data
    let key = DataKey::User(user.clone());
    env.storage().persistent().set(&key, &new_user);

    // Extend TTL for new user
    ttl::extend_user_ttl(env, &user);

    // Initialize user rewards
    let _ = crate::rewards::storage::initialize_user_rewards(env, user);

    Ok(())
}
