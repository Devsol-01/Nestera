use soroban_sdk::{Address, Env, Vec};

use crate::errors::SavingsError;
use crate::storage_types::{DataKey, LockSave};
use crate::users;

/// Creates a new Lock Save plan for a user
///
/// # Arguments
/// * `env` - The contract environment
/// * `user` - The address of the user creating the lock save
/// * `amount` - The amount to lock (must be positive)
/// * `duration` - The lock duration in seconds (must be positive)
///
/// # Returns
/// `Ok(lock_id)` on success, `Err(SavingsError)` on failure
///
/// # Errors
/// * `ContractPaused` - If contract is currently paused
/// * `InvalidAmount` - If amount is zero or negative
/// * `InvalidTimestamp` - If duration is zero or negative
/// * `UserNotFound` - If user doesn't exist in the system
/// * `Overflow` - If timestamp calculations overflow
pub fn create_lock_save(
    env: &Env,
    user: Address,
    amount: i128,
    duration: u64,
) -> Result<u64, SavingsError> {
    // Require authorization from the user
    user.require_auth();

    // Check if contract is paused
    let is_paused: bool = env
        .storage()
        .persistent()
        .get(&DataKey::Paused)
        .unwrap_or(false);

    if is_paused {
        return Err(SavingsError::ContractPaused);
    }

    // Validate inputs
    if amount <= 0 {
        return Err(SavingsError::InvalidAmount);
    }

    if duration == 0 {
        return Err(SavingsError::InvalidTimestamp);
    }

    // Ensure user exists
    if !users::user_exists(env, &user) {
        return Err(SavingsError::UserNotFound);
    }

    // Get current timestamp
    let current_time = env.ledger().timestamp();

    // Calculate maturity time, checking for overflow
    let maturity_time = current_time
        .checked_add(duration)
        .ok_or(SavingsError::Overflow)?;

    // Get next lock ID
    let lock_id = get_next_lock_id(env);

    // Create the LockSave struct
    let lock_save = LockSave {
        id: lock_id,
        owner: user.clone(),
        amount,
        interest_rate: 500, // Default 5% APY
        start_time: current_time,
        maturity_time,
        is_withdrawn: false,
    };

    // Store the LockSave
    env.storage()
        .persistent()
        .set(&DataKey::LockSave(lock_id), &lock_save);

    // Add lock_id to user's list of lock saves
    add_lock_to_user(env, &user, lock_id);

    // Increment the next lock ID
    increment_next_lock_id(env);

    // Emit event
    env.events().publish(
        (soroban_sdk::symbol_short!("lock_save"), user, lock_id),
        amount,
    );

    Ok(lock_id)
}

/// Checks if a lock save plan has matured
///
/// # Arguments
/// * `env` - The contract environment
/// * `lock_id` - The ID of the lock save to check
///
/// # Returns
/// `true` if the lock save has matured, `false` otherwise
pub fn check_matured_lock(env: &Env, lock_id: u64) -> bool {
    if let Some(lock_save) = get_lock_save(env, lock_id) {
        let current_time = env.ledger().timestamp();
        current_time >= lock_save.maturity_time
    } else {
        false
    }
}

/// Retrieves a lock save by ID
///
/// # Arguments
/// * `env` - The contract environment
/// * `lock_id` - The ID of the lock save to retrieve
///
/// # Returns
/// `Some(LockSave)` if found, `None` otherwise
pub fn get_lock_save(env: &Env, lock_id: u64) -> Option<LockSave> {
    env.storage().persistent().get(&DataKey::LockSave(lock_id))
}

/// Retrieves all lock save IDs for a user
///
/// # Arguments
/// * `env` - The contract environment
/// * `user` - The user's address
///
/// # Returns
/// Vector of lock save IDs owned by the user
pub fn get_user_lock_saves(env: &Env, user: &Address) -> Vec<u64> {
    env.storage()
        .persistent()
        .get(&DataKey::UserLockSaves(user.clone()))
        .unwrap_or_else(|| Vec::new(env))
}

/// Withdraws from a matured lock save plan
///
/// # Arguments
/// * `env` - The contract environment
/// * `user` - The user attempting to withdraw
/// * `lock_id` - The ID of the lock save to withdraw from
///
/// # Returns
/// `Ok(amount)` on success, `Err(SavingsError)` on failure
///
/// # Errors
/// * `ContractPaused` - If contract is currently paused
/// * `PlanNotFound` - If lock save doesn't exist
/// * `Unauthorized` - If user is not the owner
/// * `TooEarly` - If lock save hasn't matured yet
/// * `PlanCompleted` - If already withdrawn
pub fn withdraw_lock_save(env: &Env, user: Address, lock_id: u64) -> Result<i128, SavingsError> {
    // Require authorization from the user
    user.require_auth();

    // Check if contract is paused
    let is_paused: bool = env
        .storage()
        .persistent()
        .get(&DataKey::Paused)
        .unwrap_or(false);

    if is_paused {
        return Err(SavingsError::ContractPaused);
    }

    // Get the lock save
    let mut lock_save = get_lock_save(env, lock_id).ok_or(SavingsError::PlanNotFound)?;

    // Verify ownership
    if lock_save.owner != user {
        return Err(SavingsError::Unauthorized);
    }

    // Check if already withdrawn
    if lock_save.is_withdrawn {
        return Err(SavingsError::PlanCompleted);
    }

    // Check if matured
    if !check_matured_lock(env, lock_id) {
        return Err(SavingsError::TooEarly);
    }

    // Mark as withdrawn
    lock_save.is_withdrawn = true;

    // Update storage
    env.storage()
        .persistent()
        .set(&DataKey::LockSave(lock_id), &lock_save);

    // Calculate final amount with interest (simplified calculation)
    let final_amount = calculate_lock_save_yield(&lock_save, env.ledger().timestamp());

    // Emit withdrawal event
    env.events().publish(
        (soroban_sdk::symbol_short!("withdraw"), user, lock_id),
        final_amount,
    );

    Ok(final_amount)
}

/// Gets the next available lock ID and initializes if needed
fn get_next_lock_id(env: &Env) -> u64 {
    env.storage()
        .persistent()
        .get(&DataKey::NextLockId)
        .unwrap_or(1u64)
}

/// Increments the next lock ID counter
fn increment_next_lock_id(env: &Env) {
    let current_id = get_next_lock_id(env);
    env.storage()
        .persistent()
        .set(&DataKey::NextLockId, &(current_id + 1));
}

/// Adds a lock save ID to a user's list
fn add_lock_to_user(env: &Env, user: &Address, lock_id: u64) {
    let mut user_locks = get_user_lock_saves(env, user);
    user_locks.push_back(lock_id);
    env.storage()
        .persistent()
        .set(&DataKey::UserLockSaves(user.clone()), &user_locks);
}

/// Calculates the yield for a lock save plan
/// This is a simplified calculation - in production you might want more sophisticated interest calculations
fn calculate_lock_save_yield(lock_save: &LockSave, current_time: u64) -> i128 {
    let duration_seconds = current_time.saturating_sub(lock_save.start_time);
    let duration_years = duration_seconds as f64 / (365.25 * 24.0 * 3600.0);

    // Simple interest calculation: amount * (1 + rate * time)
    let rate_decimal = lock_save.interest_rate as f64 / 10000.0; // Convert basis points to decimal
    let multiplier = 1.0 + (rate_decimal * duration_years);

    (lock_save.amount as f64 * multiplier) as i128
}

#[cfg(test)]
mod tests {
    use crate::{NesteraContract, NesteraContractClient};
    use soroban_sdk::{
        testutils::{Address as _, Ledger},
        Address, Env,
    };

    fn setup_test_env() -> (Env, NesteraContractClient<'static>) {
        let env = Env::default();
        let contract_id = env.register(NesteraContract, ());
        let client = NesteraContractClient::new(&env, &contract_id);
        (env, client)
    }

    #[test]
    fn test_create_lock_save_success() {
        let (env, client) = setup_test_env();
        let user = Address::generate(&env);

        env.mock_all_auths();

        // Initialize user first
        client.initialize_user(&user);

        let amount = 1000i128;
        let duration = 86400u64; // 1 day

        let lock_id = client.create_lock_save(&user, &amount, &duration);
        assert_eq!(lock_id, 1);

        // Verify the lock save was stored
        let lock_save = client.get_lock_save_detail(&lock_id);
        assert_eq!(lock_save.id, lock_id);
        assert_eq!(lock_save.owner, user);
        assert_eq!(lock_save.amount, amount);
        assert_eq!(lock_save.interest_rate, 500);
        assert!(!lock_save.is_withdrawn);

        // Verify user has the lock save in their list
        let user_locks = client.get_user_lock_saves(&user);
        assert_eq!(user_locks.len(), 1);
        assert_eq!(user_locks.get(0).unwrap(), lock_id);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #41)")]
    fn test_create_lock_save_invalid_amount() {
        let (env, client) = setup_test_env();
        let user = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user);

        client.create_lock_save(&user, &0, &86400u64);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #50)")]
    fn test_create_lock_save_invalid_duration() {
        let (env, client) = setup_test_env();
        let user = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user);

        client.create_lock_save(&user, &1000, &0);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #10)")]
    fn test_create_lock_save_user_not_found() {
        let (env, client) = setup_test_env();
        let user = Address::generate(&env);

        env.mock_all_auths();

        // Don't initialize user
        client.create_lock_save(&user, &1000, &86400u64);
    }

    #[test]
    fn test_check_matured_lock_not_matured() {
        let (env, client) = setup_test_env();
        let user = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user);

        let lock_id = client.create_lock_save(&user, &1000, &86400u64);

        // Should not be matured immediately
        assert!(!client.check_matured_lock(&lock_id));
    }

    #[test]
    fn test_check_matured_lock_matured() {
        let (env, client) = setup_test_env();
        env.ledger().with_mut(|li| {
            li.timestamp = 1000;
        });

        let user = Address::generate(&env);
        env.mock_all_auths();
        client.initialize_user(&user);

        let lock_id = client.create_lock_save(&user, &1000, &100u64);

        // Advance time past maturity
        env.ledger().with_mut(|li| {
            li.timestamp = 1200; // 1000 + 100 + buffer
        });

        assert!(client.check_matured_lock(&lock_id));
    }

    #[test]
    fn test_check_matured_lock_nonexistent() {
        let (_env, client) = setup_test_env();

        // Non-existent lock should return false
        assert!(!client.check_matured_lock(&999));
    }

    #[test]
    fn test_withdraw_lock_save_success() {
        let (env, client) = setup_test_env();
        env.ledger().with_mut(|li| {
            li.timestamp = 1000;
        });

        let user = Address::generate(&env);
        env.mock_all_auths();
        client.initialize_user(&user);

        let lock_id = client.create_lock_save(&user, &1000, &100u64);

        // Advance time past maturity
        env.ledger().with_mut(|li| {
            li.timestamp = 1200;
        });

        let amount = client.withdraw_lock_save(&user, &lock_id);
        assert!(amount >= 1000); // Should include some interest

        // Verify lock save is marked as withdrawn
        let lock_save = client.get_lock_save_detail(&lock_id);
        assert!(lock_save.is_withdrawn);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #51)")]
    fn test_withdraw_lock_save_not_matured() {
        let (env, client) = setup_test_env();
        let user = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user);

        let lock_id = client.create_lock_save(&user, &1000, &86400u64);

        client.withdraw_lock_save(&user, &lock_id);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #23)")]
    fn test_withdraw_lock_save_already_withdrawn() {
        let (env, client) = setup_test_env();
        env.ledger().with_mut(|li| {
            li.timestamp = 1000;
        });

        let user = Address::generate(&env);
        env.mock_all_auths();
        client.initialize_user(&user);

        let lock_id = client.create_lock_save(&user, &1000, &100u64);

        // Advance time past maturity
        env.ledger().with_mut(|li| {
            li.timestamp = 1200;
        });

        // First withdrawal should succeed
        client.withdraw_lock_save(&user, &lock_id);

        // Second withdrawal should fail
        client.withdraw_lock_save(&user, &lock_id);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1)")]
    fn test_withdraw_lock_save_unauthorized() {
        let (env, client) = setup_test_env();
        env.ledger().with_mut(|li| {
            li.timestamp = 1000;
        });

        let user1 = Address::generate(&env);
        let user2 = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user1);
        client.initialize_user(&user2);

        let lock_id = client.create_lock_save(&user1, &1000, &100u64);

        // Advance time past maturity
        env.ledger().with_mut(|li| {
            li.timestamp = 1200;
        });

        // User2 trying to withdraw user1's lock save should fail
        client.withdraw_lock_save(&user2, &lock_id);
    }

    #[test]
    fn test_multiple_lock_saves_unique_ids() {
        let (env, client) = setup_test_env();
        let user = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user);

        let lock_id1 = client.create_lock_save(&user, &1000, &86400u64);
        let lock_id2 = client.create_lock_save(&user, &2000, &172800u64);

        assert_ne!(lock_id1, lock_id2);
        assert_eq!(lock_id1, 1);
        assert_eq!(lock_id2, 2);

        // Verify user has both lock saves
        let user_locks = client.get_user_lock_saves(&user);
        assert_eq!(user_locks.len(), 2);

        // Check that both lock IDs are present
        let lock_id1_found = (0..user_locks.len()).any(|i| user_locks.get(i).unwrap() == lock_id1);
        let lock_id2_found = (0..user_locks.len()).any(|i| user_locks.get(i).unwrap() == lock_id2);

        assert!(lock_id1_found);
        assert!(lock_id2_found);
    }
}
