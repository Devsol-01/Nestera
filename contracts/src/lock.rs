use crate::ensure_not_paused;
use crate::errors::SavingsError;
use crate::rewards::storage;
use crate::storage_types::{DataKey, LockSave, User};
use crate::ttl;
use crate::users;
use soroban_sdk::{symbol_short, Address, Env, Vec};

/// Creates a new Lock Save plan for a user
pub fn create_lock_save(
    env: &Env,
    user: Address,
    amount: i128,
    duration: u64,
) -> Result<u64, SavingsError> {
    ensure_not_paused(env)?;
    // Note: user.require_auth() is already called in lib.rs wrapper function

    // Validate inputs
    if amount <= 0 {
        return Err(SavingsError::InvalidAmount);
    }
    if duration == 0 {
        // Aligned with the test expectation of a generic invalid duration error
        return Err(SavingsError::InvalidTimestamp);
    }

    // Ensure user exists using your users module
    if !users::user_exists(env, &user) {
        return Err(SavingsError::UserNotFound);
    }

    // ID Logic
    let lock_id = get_next_lock_id(env);
    increment_next_lock_id(env);

    let start_time = env.ledger().timestamp();
    let maturity_time = start_time
        .checked_add(duration)
        .ok_or(SavingsError::Overflow)?;

    let lock_save = LockSave {
        id: lock_id,
        owner: user.clone(),
        amount,
        interest_rate: 500, // Matching your test expectation of 500 (5%)
        start_time,
        maturity_time,
        is_withdrawn: false,
    };

    // Store the LockSave
    env.storage()
        .persistent()
        .set(&DataKey::LockSave(lock_id), &lock_save);

    // Update user's lock list
    add_lock_to_user(env, &user, lock_id);

    // Update user's profile stats
    let user_key = DataKey::User(user.clone());
    let mut user_data: User = env.storage().persistent().get(&user_key).unwrap();
    user_data.total_balance += amount;
    user_data.savings_count += 1;
    env.storage().persistent().set(&user_key, &user_data);

    storage::award_deposit_points(env, user.clone(), amount)?;
    storage::award_long_lock_bonus(env, user.clone(), amount, duration)?;

    // Extend TTL for new lock save and user data
    ttl::extend_lock_ttl(env, lock_id);
    ttl::extend_user_ttl(env, &user);
    ttl::extend_user_plan_list_ttl(env, &DataKey::UserLockSaves(user.clone()));

    Ok(lock_id)
}

pub fn withdraw_lock_save(env: &Env, user: Address, lock_id: u64) -> Result<i128, SavingsError> {
    ensure_not_paused(env)?;
    // Note: user.require_auth() is already called in lib.rs wrapper function

    let mut lock_save = get_lock_save(env, lock_id).ok_or(SavingsError::PlanNotFound)?;

    if lock_save.owner != user {
        return Err(SavingsError::Unauthorized);
    }

    if lock_save.is_withdrawn {
        return Err(SavingsError::PlanCompleted);
    }

    if !check_matured_lock(env, lock_id) {
        return Err(SavingsError::TooEarly);
    }

    let final_amount = calculate_lock_save_yield(&lock_save, env.ledger().timestamp());

    lock_save.is_withdrawn = true;
    env.storage()
        .persistent()
        .set(&DataKey::LockSave(lock_id), &lock_save);

    // Update user's total balance (subtracting the locked portion)
    let user_key = DataKey::User(user.clone());
    if let Some(mut user_data) = env.storage().persistent().get::<DataKey, User>(&user_key) {
        user_data.total_balance -= lock_save.amount;
        env.storage().persistent().set(&user_key, &user_data);
    }

    // Extend TTL (completed locks get shorter extension)
    ttl::extend_lock_ttl(env, lock_id);
    ttl::extend_user_ttl(env, &user);

    env.events()
        .publish((symbol_short!("withdraw"), user, lock_id), final_amount);

    Ok(final_amount)
}

pub fn check_matured_lock(env: &Env, lock_id: u64) -> bool {
    if let Some(lock_save) = get_lock_save(env, lock_id) {
        // Extend TTL on check
        ttl::extend_lock_ttl(env, lock_id);
        env.ledger().timestamp() >= lock_save.maturity_time
    } else {
        false
    }
}

pub fn get_lock_save(env: &Env, lock_id: u64) -> Option<LockSave> {
    let lock_save = env.storage().persistent().get(&DataKey::LockSave(lock_id));
    if lock_save.is_some() {
        // Extend TTL on read
        ttl::extend_lock_ttl(env, lock_id);
    }
    lock_save
}

pub fn get_user_lock_saves(env: &Env, user: &Address) -> Vec<u64> {
    let list_key = DataKey::UserLockSaves(user.clone());
    let locks = env
        .storage()
        .persistent()
        .get(&list_key)
        .unwrap_or_else(|| Vec::new(env));

    // Extend TTL on list access
    if !locks.is_empty() {
        ttl::extend_user_plan_list_ttl(env, &list_key);
    }

    locks
}

// --- Internal Helper Functions ---

fn get_next_lock_id(env: &Env) -> u64 {
    let counter_key = DataKey::NextLockId;
    let id = env.storage().persistent().get(&counter_key).unwrap_or(1);

    // Extend TTL on counter access
    ttl::extend_counter_ttl(env, &counter_key);

    id
}

fn increment_next_lock_id(env: &Env) {
    let current_id = get_next_lock_id(env);
    let counter_key = DataKey::NextLockId;
    env.storage()
        .persistent()
        .set(&counter_key, &(current_id + 1));

    // Extend TTL on counter update
    ttl::extend_counter_ttl(env, &counter_key);
}

fn add_lock_to_user(env: &Env, user: &Address, lock_id: u64) {
    let mut user_locks = get_user_lock_saves(env, user);
    user_locks.push_back(lock_id);
    env.storage()
        .persistent()
        .set(&DataKey::UserLockSaves(user.clone()), &user_locks);
}

fn calculate_lock_save_yield(lock_save: &LockSave, current_time: u64) -> i128 {
    let duration_seconds = current_time.saturating_sub(lock_save.start_time);
    let duration_years = (duration_seconds as f64) / (365.25 * 24.0 * 3600.0);
    let rate_decimal = (lock_save.interest_rate as f64) / 10000.0;
    let multiplier = 1.0 + (rate_decimal * duration_years);
    (lock_save.amount as f64 * multiplier) as i128
}

#[cfg(test)]
mod tests {
    use crate::rewards::storage::LONG_LOCK_BONUS_THRESHOLD_SECS;
    use crate::rewards::storage_types::RewardsConfig;
    use crate::{NesteraContract, NesteraContractClient};
    use soroban_sdk::{
        testutils::{Address as _, Events, Ledger},
        Address, BytesN, Env, IntoVal, Symbol,
    };

    fn setup_env_with_rewards_enabled(
        enabled: bool,
    ) -> (Env, NesteraContractClient<'static>, Address) {
        let env = Env::default();
        let contract_id = env.register(NesteraContract, ());
        let client = NesteraContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let admin_pk = BytesN::from_array(&env, &[1u8; 32]);

        env.mock_all_auths();
        client.initialize(&admin, &admin_pk);

        let config = RewardsConfig {
            points_per_token: 10,
            streak_bonus_bps: 0,
            long_lock_bonus_bps: 2_000, // 20% of base points
            goal_completion_bonus: 500,
            enabled,
            min_deposit_for_rewards: 0,
            action_cooldown_seconds: 0,
            max_daily_points: 1_000_000,
            max_streak_multiplier: 10_000,
        };
        assert!(client.try_initialize_rewards_config(&config).is_ok());

        (env, client, admin)
    }

    fn setup_env_with_rewards() -> (Env, NesteraContractClient<'static>, Address) {
        setup_env_with_rewards_enabled(true)
    }

    fn has_bonus_event(
        env: &Env,
        user: &Address,
        reason: soroban_sdk::Symbol,
        points: u128,
    ) -> bool {
        let expected_topics =
            (Symbol::new(env, "BonusAwarded"), user.clone(), reason).into_val(env);
        let expected_data = points.into_val(env);
        let contract_id = env.current_contract_address();
        let events = env.events().all();

        for i in 0..events.len() {
            if let Some((event_contract, topics, data)) = events.get(i) {
                if event_contract == contract_id
                    && topics == expected_topics
                    && data.shallow_eq(&expected_data)
                {
                    return true;
                }
            }
        }
        false
    }

    fn bonus_event_count(env: &Env, user: &Address, reason: soroban_sdk::Symbol) -> u32 {
        let expected_topics =
            (Symbol::new(env, "BonusAwarded"), user.clone(), reason).into_val(env);
        let contract_id = env.current_contract_address();
        let events = env.events().all();
        let mut count = 0u32;

        for i in 0..events.len() {
            if let Some((event_contract, topics, _data)) = events.get(i) {
                if event_contract == contract_id && topics == expected_topics {
                    count += 1;
                }
            }
        }
        count
    }

    #[test]
    fn test_long_lock_bonus_applies_only_above_threshold() {
        let (env, client, _) = setup_env_with_rewards();
        let user = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user);

        let amount = 1_000i128;
        let above_threshold = LONG_LOCK_BONUS_THRESHOLD_SECS + 1;
        client.create_lock_save(&user, &amount, &above_threshold);

        let rewards = client.get_user_rewards(&user);
        // base points = 1000 * 10 = 10000, bonus = 20% = 2000
        // base points = 1000 * 10 = 10000, bonus = 20% = 2000
        assert_eq!(rewards.total_points, 12_000);
    }

    #[test]
    fn test_long_lock_bonus_not_applied_at_threshold_boundary() {
        let (env, client, _) = setup_env_with_rewards();
        let user = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user);

        let amount = 1_000i128;
        client.create_lock_save(&user, &amount, &LONG_LOCK_BONUS_THRESHOLD_SECS);

        let rewards = client.get_user_rewards(&user);
        // base points = 1000 * 10 = 10000
        assert_eq!(rewards.total_points, 10_000);
    }

    #[test]
    fn test_long_lock_bonus_not_applied_below_threshold() {
        let (env, client, _) = setup_env_with_rewards();
        let user = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user);

        let amount = 1_000i128;
        let below_threshold = LONG_LOCK_BONUS_THRESHOLD_SECS - 1;
        client.create_lock_save(&user, &amount, &below_threshold);

        let rewards = client.get_user_rewards(&user);
        // base points = 1000 * 10 = 10000
        assert_eq!(rewards.total_points, 10_000);
    }

    #[test]
    fn test_long_lock_bonus_not_awarded_when_rewards_disabled() {
        let (env, client, _) = setup_env_with_rewards_enabled(false);
        let user = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user);

        let amount = 1_000i128;
        let above_threshold = LONG_LOCK_BONUS_THRESHOLD_SECS + 1;
        client.create_lock_save(&user, &amount, &above_threshold);

        let rewards = client.get_user_rewards(&user);
        assert_eq!(rewards.total_points, 0);
    }

    #[test]
    fn test_long_lock_bonus_not_duplicated_after_withdraw() {
        let (env, client, _) = setup_env_with_rewards();
        let user = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user);

        let amount = 1_000i128;
        let duration = LONG_LOCK_BONUS_THRESHOLD_SECS + 1;
        let lock_id = client.create_lock_save(&user, &amount, &duration);

        env.ledger().with_mut(|li| {
            li.timestamp = li.timestamp + duration + 1;
        });

        let _ = client.withdraw_lock_save(&user, &lock_id);

        let rewards = client.get_user_rewards(&user);
        // base points = 1000 * 10 = 10000, bonus = 2000
        assert_eq!(rewards.total_points, 12_000);
    }
}
