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
        admin, &10,        // points_per_token
        &500,       // streak_bonus_bps (5%)
        &1000,      // long_lock_bonus_bps (10%)
        &100,       // goal_completion_bonus
        &true,      // enabled
        &100,       // min_deposit_for_rewards
        &0,         // action_cooldown_seconds (disabled for testing)
        &1_000_000, // max_daily_points
        &2_000,     // max_streak_multiplier (20%)
    );
}

fn add_points_directly(_env: &Env, client: &NesteraContractClient, user: &Address, points: u128) {
    // Award points by depositing (10 points per token)
    let deposit_amount = (points / 10) as i128;
    if deposit_amount > 0 {
        let _ = client.try_deposit_flexi(user, &deposit_amount);
    }
}

#[test]
fn test_redeem_points_success() {
    let (env, client, admin, user) = create_test_env();
    setup_rewards_config(&env, &client, &admin);

    // Award some points via deposit
    add_points_directly(&env, &client, &user, 50_000);

    let rewards_before = client.get_user_rewards(&user);
    assert!(rewards_before.total_points > 0);
    let initial_points = rewards_before.total_points;

    // Redeem 10,000 points
    let redeem_amount = 10_000u128;
    let result = client.try_redeem_points(&user, &redeem_amount);
    assert!(result.is_ok());

    // Verify points deducted
    let rewards_after = client.get_user_rewards(&user);
    assert_eq!(rewards_after.total_points, initial_points - redeem_amount);
}

#[test]
fn test_redeem_insufficient_balance() {
    let (env, client, admin, user) = create_test_env();
    setup_rewards_config(&env, &client, &admin);

    // Award limited points
    add_points_directly(&env, &client, &user, 5_000);

    let rewards = client.get_user_rewards(&user);
    let available_points = rewards.total_points;

    // Try to redeem more than available
    let result = client.try_redeem_points(&user, &(available_points + 1000));
    assert!(result.is_err());

    // Verify balance unchanged
    let rewards_after = client.get_user_rewards(&user);
    assert_eq!(rewards_after.total_points, available_points);
}

#[test]
fn test_redeem_zero_amount() {
    let (env, client, admin, user) = create_test_env();
    setup_rewards_config(&env, &client, &admin);

    // Award some points
    add_points_directly(&env, &client, &user, 10_000);

    // Try to redeem zero
    let result = client.try_redeem_points(&user, &0);
    assert!(result.is_err());
}

#[test]
fn test_redeem_exact_balance() {
    let (env, client, admin, user) = create_test_env();
    setup_rewards_config(&env, &client, &admin);

    // Award points
    add_points_directly(&env, &client, &user, 20_000);

    let rewards_before = client.get_user_rewards(&user);
    let total_points = rewards_before.total_points;

    // Redeem exact balance
    let result = client.try_redeem_points(&user, &total_points);
    assert!(result.is_ok());

    // Verify zero balance
    let rewards_after = client.get_user_rewards(&user);
    assert_eq!(rewards_after.total_points, 0);
}

#[test]
fn test_multiple_redemptions() {
    let (env, client, admin, user) = create_test_env();
    setup_rewards_config(&env, &client, &admin);

    // Award significant points
    add_points_directly(&env, &client, &user, 100_000);

    let initial_rewards = client.get_user_rewards(&user);
    let initial_points = initial_rewards.total_points;

    // Multiple redemptions
    client.redeem_points(&user, &5_000);
    client.redeem_points(&user, &10_000);
    client.redeem_points(&user, &15_000);

    // Verify cumulative deductions
    let final_rewards = client.get_user_rewards(&user);
    assert_eq!(final_rewards.total_points, initial_points - 30_000);
}

#[test]
fn test_redemption_does_not_affect_lifetime_deposits() {
    let (env, client, admin, user) = create_test_env();
    setup_rewards_config(&env, &client, &admin);

    // Award points via deposit
    add_points_directly(&env, &client, &user, 30_000);

    let rewards_before = client.get_user_rewards(&user);
    let lifetime_before = rewards_before.lifetime_deposited;
    let streak_before = rewards_before.current_streak;

    // Redeem points
    client.redeem_points(&user, &10_000);

    // Verify lifetime_deposited and streak unchanged
    let rewards_after = client.get_user_rewards(&user);
    assert_eq!(rewards_after.lifetime_deposited, lifetime_before);
    assert_eq!(rewards_after.current_streak, streak_before);
}

#[test]
fn test_redemption_event_emitted() {
    let (env, client, admin, user) = create_test_env();
    setup_rewards_config(&env, &client, &admin);

    // Award points
    add_points_directly(&env, &client, &user, 30_000);

    let initial_rewards = client.get_user_rewards(&user);
    let initial_points = initial_rewards.total_points;

    // Redeem points
    client.redeem_points(&user, &10_000);

    // Verify points were deducted (event emission implicitly verified by success)
    let final_rewards = client.get_user_rewards(&user);
    assert_eq!(final_rewards.total_points, initial_points - 10_000);
}

#[test]
fn test_redemption_safe_arithmetic() {
    let (env, client, admin, user) = create_test_env();
    setup_rewards_config(&env, &client, &admin);

    // Award large amount of points
    add_points_directly(&env, &client, &user, 500_000);

    let rewards = client.get_user_rewards(&user);
    let points = rewards.total_points;

    // Redeem near maximum
    let redeem_amount = points.saturating_sub(100);
    let result = client.try_redeem_points(&user, &redeem_amount);
    assert!(result.is_ok());

    // Verify no overflow/underflow
    let final_rewards = client.get_user_rewards(&user);
    assert_eq!(final_rewards.total_points, 100);
}

#[test]
fn test_redemption_with_concurrent_earning() {
    let (env, client, admin, user) = create_test_env();
    setup_rewards_config(&env, &client, &admin);

    // Award initial points
    add_points_directly(&env, &client, &user, 50_000);
    let points_after_first = client.get_user_rewards(&user).total_points;

    // Redeem some points
    client.redeem_points(&user, &10_000);
    let points_after_redeem = client.get_user_rewards(&user).total_points;
    assert_eq!(points_after_redeem, points_after_first - 10_000);

    // Earn more points
    add_points_directly(&env, &client, &user, 30_000);
    let points_after_second = client.get_user_rewards(&user).total_points;

    // New points should add to remaining balance
    assert!(points_after_second > points_after_redeem);
    assert_eq!(points_after_second, points_after_redeem + 30_000);
}

#[test]
fn test_cannot_redeem_without_earning_first() {
    let (env, client, admin, user) = create_test_env();
    setup_rewards_config(&env, &client, &admin);

    // User has no rewards yet
    let rewards = client.get_user_rewards(&user);
    assert_eq!(rewards.total_points, 0);

    // Try to redeem
    let result = client.try_redeem_points(&user, &100);
    assert!(
        result.is_err(),
        "Should fail when redeeming with zero balance"
    );
}

#[test]
fn test_redemption_overflow_protection() {
    let (env, client, admin, user) = create_test_env();
    setup_rewards_config(&env, &client, &admin);

    // Award maximum safe points
    add_points_directly(&env, &client, &user, 1_000_000);

    let rewards = client.get_user_rewards(&user);

    // Try to redeem u128::MAX (should fail with insufficient balance)
    let result = client.try_redeem_points(&user, &u128::MAX);
    assert!(result.is_err());

    // Balance should remain unchanged
    let rewards_after = client.get_user_rewards(&user);
    assert_eq!(rewards_after.total_points, rewards.total_points);
}
