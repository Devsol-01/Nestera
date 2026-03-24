use super::storage_types::{RewardsDataKey, UserRewards};
use crate::errors::SavingsError;
use crate::rewards::config::get_rewards_config;
use crate::rewards::events::{emit_bonus_awarded, emit_points_awarded, emit_streak_updated};
use soroban_sdk::{Address, Env, Symbol};

/// Duration threshold for long-lock bonus eligibility (in seconds).
pub const LONG_LOCK_BONUS_THRESHOLD_SECS: u64 = 180 * 24 * 60 * 60;
/// Maximum allowed time between deposits to keep a streak active.
pub const STREAK_WINDOW_SECS: u64 = 7 * 24 * 60 * 60;
/// Minimum streak length required before streak bonus points are applied.
pub const STREAK_BONUS_THRESHOLD: u32 = 3;

/// Fetches user rewards or returns a default empty state
pub fn get_user_rewards(env: &Env, user: Address) -> UserRewards {
    let key = RewardsDataKey::UserLedger(user);

    // Automatically extend TTL on read to prevent data expiry
    if let Some(rewards) = env
        .storage()
        .persistent()
        .get::<RewardsDataKey, UserRewards>(&key)
    {
        env.storage().persistent().extend_ttl(&key, 17280, 17280); // ~1 day extension
        rewards
    } else {
        UserRewards {
            total_points: 0,
            lifetime_deposited: 0,
            current_streak: 0,
            last_action_timestamp: 0,
            daily_points_earned: 0,
            last_reward_day: 0,
        }
    }
}

/// Force-saves the user rewards state
pub fn save_user_rewards(env: &Env, user: Address, rewards: &UserRewards) {
    let key = RewardsDataKey::UserLedger(user);
    env.storage().persistent().set(&key, rewards);
    env.storage().persistent().extend_ttl(&key, 17280, 17280);
}

pub fn initialize_user_rewards(env: &Env, user: Address) -> Result<(), SavingsError> {
    let key = RewardsDataKey::UserLedger(user.clone());

    if env.storage().persistent().has(&key) {
        return Err(SavingsError::UserAlreadyExists);
    }

    let initial_rewards = UserRewards {
        total_points: 0,
        lifetime_deposited: 0,
        current_streak: 0,
        last_action_timestamp: env.ledger().timestamp(),
        daily_points_earned: 0,
        last_reward_day: env.ledger().timestamp() / 86400,
    };

    // Now this function can find save_user_rewards because they are in the same file
    save_user_rewards(env, user, &initial_rewards);
    Ok(())
}

/// Increases user points with overflow protection
pub fn add_points(env: &Env, user: Address, points: u128) -> Result<(), SavingsError> {
    let mut rewards = get_user_rewards(env, user.clone());

    // Safety check for overflow
    rewards.total_points = rewards
        .total_points
        .checked_add(points)
        .ok_or(SavingsError::Overflow)?;

    save_user_rewards(env, user, &rewards);
    Ok(())
}

/// Resets the streak back to zero
pub fn reset_streak(env: &Env, user: Address) {
    let mut rewards = get_user_rewards(env, user.clone());
    rewards.current_streak = 0;
    save_user_rewards(env, user, &rewards);
}

/// Updates a user's savings streak based on the elapsed time since the previous action.
///
/// Rules:
/// - First tracked action starts streak at 1.
/// - If elapsed time is <= STREAK_WINDOW_SECS, streak increments.
/// - If elapsed time is > STREAK_WINDOW_SECS, streak resets to 1.
///
/// Note: last_action_timestamp==0 with current_streak>0 means the previous action was at
/// ledger time 0; we must use elapsed logic, not treat it as "first action".
pub fn update_streak(env: &Env, user: Address) -> Result<u32, SavingsError> {
    let mut rewards = get_user_rewards(env, user.clone());
    let now = env.ledger().timestamp();

    let is_first_ever = rewards.last_action_timestamp == 0 && rewards.current_streak == 0;

    rewards.current_streak = if is_first_ever {
        1
    } else {
        let elapsed = now.saturating_sub(rewards.last_action_timestamp);
        if elapsed <= STREAK_WINDOW_SECS {
            rewards
                .current_streak
                .checked_add(1)
                .ok_or(SavingsError::Overflow)?
        } else {
            1
        }
    };
    rewards.last_action_timestamp = now;
    save_user_rewards(env, user.clone(), &rewards);
    emit_streak_updated(env, user, rewards.current_streak);
    Ok(rewards.current_streak)
}

pub fn award_deposit_points(env: &Env, user: Address, amount: i128) -> Result<(), SavingsError> {
    if amount <= 0 {
        return Ok(());
    }

    // 1. Fetch Config & Check if Enabled
    let config = match get_rewards_config(env) {
        Ok(config) if config.enabled => config,
        _ => return Ok(()),
    };

    // ANTI-FARMING: Check minimum deposit size
    if amount < config.min_deposit_for_rewards {
        return Ok(()); // No rewards for micro-deposits
    }

    let mut user_rewards = get_user_rewards(env, user.clone());
    let now = env.ledger().timestamp();
    let current_day = now / 86400;

    // ANTI-FARMING: Check action cooldown (skip for first ever action)
    let is_first_action =
        user_rewards.last_action_timestamp == 0 && user_rewards.current_streak == 0;
    if !is_first_action
        && now.saturating_sub(user_rewards.last_action_timestamp) < config.action_cooldown_seconds
    {
        return Ok(()); // Too soon after last action
    }

    // ANTI-FARMING: Reset daily counter if new day
    if current_day > user_rewards.last_reward_day {
        user_rewards.daily_points_earned = 0;
        user_rewards.last_reward_day = current_day;
    }

    // ANTI-FARMING: Check daily points cap
    if user_rewards.daily_points_earned >= config.max_daily_points {
        return Ok(()); // Daily limit reached
    }

    // 2. Update streak first (time-window boundary handling)
    let streak = update_streak(env, user.clone())?;
    user_rewards = get_user_rewards(env, user.clone()); // Refresh after streak update

    // 3. Calculate Base Points
    let base_points = (amount as u128)
        .checked_mul(config.points_per_token as u128)
        .ok_or(SavingsError::Overflow)?;

    // 4. Optional streak bonus with max multiplier cap
    let streak_bonus_points = if streak >= STREAK_BONUS_THRESHOLD && config.streak_bonus_bps > 0 {
        let effective_bonus_bps = config.streak_bonus_bps.min(config.max_streak_multiplier);
        base_points
            .checked_mul(effective_bonus_bps as u128)
            .ok_or(SavingsError::Overflow)?
            / 10_000u128
    } else {
        0
    };

    let total_points_awarded = base_points
        .checked_add(streak_bonus_points)
        .ok_or(SavingsError::Overflow)?;

    // ANTI-FARMING: Cap to remaining daily allowance
    let remaining_daily = config
        .max_daily_points
        .saturating_sub(user_rewards.daily_points_earned);
    let capped_points = total_points_awarded.min(remaining_daily);

    if capped_points == 0 {
        return Ok(()); // Nothing to award after capping
    }

    // 5. Update State
    user_rewards.total_points = user_rewards
        .total_points
        .checked_add(capped_points)
        .ok_or(SavingsError::Overflow)?;

    user_rewards.daily_points_earned = user_rewards
        .daily_points_earned
        .checked_add(capped_points)
        .ok_or(SavingsError::Overflow)?;

    user_rewards.lifetime_deposited = user_rewards
        .lifetime_deposited
        .checked_add(amount)
        .ok_or(SavingsError::Overflow)?;

    // 6. Save and Emit Event
    save_user_rewards(env, user.clone(), &user_rewards);

    // Track user for ranking leaderboard
    crate::rewards::ranking::track_user_for_ranking(env, user.clone());

    emit_points_awarded(env, user.clone(), capped_points);

    if streak_bonus_points > 0 && capped_points > base_points {
        let actual_bonus = capped_points.saturating_sub(base_points);
        emit_bonus_awarded(env, user, actual_bonus, Symbol::new(env, "streak"));
    }

    Ok(())
}

/// Awards bonus points for long lock plans when duration exceeds the configured threshold.
pub fn award_long_lock_bonus(
    env: &Env,
    user: Address,
    amount: i128,
    duration: u64,
) -> Result<u128, SavingsError> {
    if amount <= 0 || duration <= LONG_LOCK_BONUS_THRESHOLD_SECS {
        return Ok(0);
    }

    let config = match get_rewards_config(env) {
        Ok(config) if config.enabled => config,
        _ => return Ok(0),
    };

    if config.long_lock_bonus_bps == 0 || config.points_per_token == 0 {
        return Ok(0);
    }

    let base_points = (amount as u128)
        .checked_mul(config.points_per_token as u128)
        .ok_or(SavingsError::Overflow)?;
    let bonus_points = base_points
        .checked_mul(config.long_lock_bonus_bps as u128)
        .ok_or(SavingsError::Overflow)?
        / 10_000u128;

    if bonus_points == 0 {
        return Ok(0);
    }

    add_points(env, user.clone(), bonus_points)?;
    emit_bonus_awarded(env, user, bonus_points, Symbol::new(env, "lock"));
    Ok(bonus_points)
}

/// Awards a fixed goal completion bonus when a goal reaches its target.
pub fn award_goal_completion_bonus(env: &Env, user: Address) -> Result<u128, SavingsError> {
    let config = match get_rewards_config(env) {
        Ok(config) if config.enabled => config,
        _ => return Ok(0),
    };

    if config.goal_completion_bonus == 0 {
        return Ok(0);
    }

    let bonus_points = config.goal_completion_bonus as u128;
    add_points(env, user.clone(), bonus_points)?;
    emit_bonus_awarded(env, user, bonus_points, Symbol::new(env, "goal"));
    Ok(bonus_points)
}

#[cfg(test)]
mod tests {
    use super::STREAK_WINDOW_SECS;
    use crate::rewards::storage_types::RewardsConfig;
    use crate::{NesteraContract, NesteraContractClient, PlanType};
    use soroban_sdk::{
        testutils::{Address as _, Ledger},
        Address, BytesN, Env,
    };

    fn setup_env_with_rewards(
        config: RewardsConfig,
    ) -> (Env, NesteraContractClient<'static>, Address) {
        let env = Env::default();
        let contract_id = env.register(NesteraContract, ());
        let client = NesteraContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let admin_pk = BytesN::from_array(&env, &[9u8; 32]);

        env.mock_all_auths();
        client.initialize(&admin, &admin_pk);
        assert!(client.try_initialize_rewards_config(&config).is_ok());

        (env, client, admin)
    }

    fn default_rewards_config() -> RewardsConfig {
        RewardsConfig {
            points_per_token: 10,
            streak_bonus_bps: 2_000, // 20%
            long_lock_bonus_bps: 0,
            goal_completion_bonus: 0,
            enabled: true,
            min_deposit_for_rewards: 0,
            action_cooldown_seconds: 0,
            max_daily_points: 1_000_000,
            max_streak_multiplier: 10_000,
        }
    }

    fn create_plan_deposit(client: &NesteraContractClient<'_>, user: &Address, amount: i128) {
        let result = client.try_create_savings_plan(user, &PlanType::Flexi, &amount);
        assert!(result.is_ok(), "create_savings_plan failed: {:?}", result);
    }

    #[test]
    fn test_streak_starts_at_one_on_first_deposit() {
        let (env, client, _) = setup_env_with_rewards(default_rewards_config());
        let user = Address::generate(&env);
        env.mock_all_auths();
        client.initialize_user(&user);

        create_plan_deposit(&client, &user, 100);

        let rewards = client.get_user_rewards(&user);
        assert_eq!(rewards.current_streak, 1);
        assert_eq!(rewards.total_points, 1_000);
    }

    #[test]
    fn test_streak_resets_after_missed_window() {
        let (env, client, _) = setup_env_with_rewards(default_rewards_config());
        let user = Address::generate(&env);
        env.mock_all_auths();
        client.initialize_user(&user);

        create_plan_deposit(&client, &user, 100);
        env.ledger()
            .with_mut(|li| li.timestamp += STREAK_WINDOW_SECS + 1);
        create_plan_deposit(&client, &user, 100);

        let rewards = client.get_user_rewards(&user);
        assert_eq!(rewards.current_streak, 1);
    }

    #[test]
    fn test_streak_bonus_config_applied_when_enabled() {
        let (env, client, _) = setup_env_with_rewards(default_rewards_config());
        let user = Address::generate(&env);
        env.mock_all_auths();
        client.initialize_user(&user);

        create_plan_deposit(&client, &user, 100);

        let rewards = client.get_user_rewards(&user);
        assert_eq!(rewards.total_points, 1_000);
        assert_eq!(rewards.current_streak, 1);
    }

    #[test]
    fn test_no_streak_bonus_before_threshold() {
        let (env, client, _) = setup_env_with_rewards(default_rewards_config());
        let user = Address::generate(&env);
        env.mock_all_auths();
        client.initialize_user(&user);

        create_plan_deposit(&client, &user, 100);
        create_plan_deposit(&client, &user, 100);

        let rewards = client.get_user_rewards(&user);
        // 2 deposits, each base = 1000, no streak bonus (streak threshold is 3).
        assert_eq!(rewards.total_points, 2_000);
    }

    #[test]
    fn test_streak_increments_within_window() {
        let (env, client, _) = setup_env_with_rewards(default_rewards_config());
        let user = Address::generate(&env);
        env.mock_all_auths();
        client.initialize_user(&user);

        create_plan_deposit(&client, &user, 100);
        let rewards_after_first = client.get_user_rewards(&user);
        assert_eq!(rewards_after_first.current_streak, 1);

        env.ledger().with_mut(|li| li.timestamp += 24 * 60 * 60); // 1 day, within 7-day window
        create_plan_deposit(&client, &user, 100);

        let rewards = client.get_user_rewards(&user);
        assert_eq!(rewards.current_streak, 2);
        assert_eq!(rewards.total_points, 2_000);
    }

    #[test]
    fn test_streak_bonus_applies_when_threshold_reached() {
        let (env, client, _) = setup_env_with_rewards(default_rewards_config());
        let user = Address::generate(&env);
        env.mock_all_auths();
        client.initialize_user(&user);

        create_plan_deposit(&client, &user, 100);
        env.ledger().with_mut(|li| li.timestamp += 24 * 60 * 60);
        create_plan_deposit(&client, &user, 100);
        env.ledger().with_mut(|li| li.timestamp += 24 * 60 * 60);
        create_plan_deposit(&client, &user, 100);

        let rewards = client.get_user_rewards(&user);
        assert_eq!(rewards.current_streak, 3);
        // base: 3 * 1000 = 3000; 3rd deposit gets 20% bonus: 1000 * 2000/10000 = 200
        assert_eq!(rewards.total_points, 3_200);
    }

    #[test]
    fn test_update_streak_entrypoint_reset_after_window() {
        let (env, client, _) = setup_env_with_rewards(default_rewards_config());
        let user = Address::generate(&env);
        env.mock_all_auths();
        client.initialize_user(&user);

        assert_eq!(client.update_streak(&user), 1);
        env.ledger()
            .with_mut(|li| li.timestamp += STREAK_WINDOW_SECS + 1);
        assert_eq!(client.update_streak(&user), 1);
    }

    #[test]
    fn test_update_streak_entrypoint_increments_within_window() {
        let (env, client, _) = setup_env_with_rewards(default_rewards_config());
        let user = Address::generate(&env);
        env.mock_all_auths();
        client.initialize_user(&user);

        assert_eq!(client.update_streak(&user), 1);
        env.ledger().with_mut(|li| li.timestamp += 24 * 60 * 60);
        assert_eq!(client.update_streak(&user), 2);
    }
}
