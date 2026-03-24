#![cfg(test)]
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env};
use Nestera::{NesteraContract, NesteraContractClient};

fn create_test_env() -> (Env, NesteraContractClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let admin_pk = BytesN::from_array(&env, &[0u8; 32]);
    client.initialize(&admin, &admin_pk);

    let user = Address::generate(&env);
    client.init_user(&user);

    (env, client, admin, user)
}

fn setup_rewards_config(_env: &Env, client: &NesteraContractClient, admin: &Address) {
    client.init_rewards_config(
        admin, &10,     // points_per_token
        &500,    // streak_bonus_bps (5%)
        &1000,   // long_lock_bonus_bps (10%)
        &100,    // goal_completion_bonus
        &true,   // enabled
        &100,    // min_deposit_for_rewards
        &60,     // action_cooldown_seconds
        &10_000, // max_daily_points
        &2_000,  // max_streak_multiplier (20%)
    );
}

#[test]
fn test_micro_deposit_spam_no_rewards() {
    let (env, client, admin, user) = create_test_env();
    setup_rewards_config(&env, &client, &admin);

    // Attempt multiple micro-deposits below minimum
    for _ in 0..100 {
        let _ = client.try_deposit_flexi(&user, &50); // Below 100 minimum
    }

    // Check user has no rewards
    let rewards = client.get_user_rewards(&user);
    assert_eq!(
        rewards.total_points, 0,
        "Micro-deposits should not earn rewards"
    );
    assert_eq!(
        rewards.daily_points_earned, 0,
        "Daily points should be zero"
    );
}

#[test]
fn test_minimum_deposit_threshold() {
    let (env, client, admin, user) = create_test_env();
    setup_rewards_config(&env, &client, &admin);

    // Verify rewards config was set up correctly
    let config = client.get_rewards_config();
    assert_eq!(
        config.min_deposit_for_rewards, 100,
        "Config should be initialized"
    );
    assert!(config.enabled, "Rewards should be enabled");

    // Deposit below minimum - should not earn rewards
    client.deposit_flexi(&user, &99);
    let rewards1 = client.get_user_rewards(&user);
    assert_eq!(
        rewards1.total_points, 0,
        "Below minimum should earn no rewards"
    );

    // Deposit at minimum - should earn rewards
    client.deposit_flexi(&user, &100);
    let rewards2 = client.get_user_rewards(&user);
    assert!(
        rewards2.total_points > 0,
        "At minimum should earn rewards: got {}",
        rewards2.total_points
    );
}

#[test]
fn test_combined_abuse_scenario() {
    let (env, client, admin, user) = create_test_env();
    setup_rewards_config(&env, &client, &admin);

    // Attempt rapid micro-deposits
    for _ in 0..50 {
        let _ = client.try_deposit_flexi(&user, &10);
    }

    // Attempt rapid valid deposits (should hit cooldown or no rewards due to micro size)
    for _ in 0..10 {
        let _ = client.try_deposit_flexi(&user, &50); // Still below minimum
    }

    let rewards_immediate = client.get_user_rewards(&user);

    // Should not get rewards from micro-deposits
    assert_eq!(
        rewards_immediate.total_points, 0,
        "Should not bypass protections with mixed micro-deposit attack"
    );
}

#[test]
fn test_daily_points_tracking() {
    let (_env, client, admin, user) = create_test_env();
    setup_rewards_config(&_env, &client, &admin);

    // Make a deposit that earns rewards
    client.deposit_flexi(&user, &1000);

    let rewards = client.get_user_rewards(&user);

    // Daily points should be tracked
    assert_eq!(
        rewards.daily_points_earned, rewards.total_points,
        "Daily points should match total on first day"
    );

    // Check that daily tracking is working (last_reward_day is set to current day)
    assert!(
        rewards.daily_points_earned > 0,
        "Daily points should be tracked after earning rewards"
    );
}

#[test]
fn test_overflow_protection_basic() {
    let (env, client, admin, user) = create_test_env();
    setup_rewards_config(&env, &client, &admin);

    // Make a large valid deposit
    client.deposit_flexi(&user, &1_000_000);

    // Should not panic or overflow
    let rewards = client.get_user_rewards(&user);
    assert!(
        rewards.total_points > 0,
        "Should accumulate points without overflow"
    );
    assert!(rewards.total_points < u128::MAX, "Should not overflow u128");
    assert!(
        rewards.lifetime_deposited > 0,
        "Should track lifetime deposits"
    );
}
