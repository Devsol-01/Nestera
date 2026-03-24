#![cfg(test)]

use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, BytesN, Env, Symbol,
};
use Nestera::{NesteraContract, NesteraContractClient};

#[test]
fn test_rewards_full_lifecycle() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let admin_pk = BytesN::from_array(&env, &[0u8; 32]);
    client.initialize(&admin, &admin_pk);

    let user = Address::generate(&env);
    client.init_user(&user);

    // 1. Initialize config
    client.init_rewards_config(
        &admin, &10,      // points_per_token
        &2000,    // streak_bonus_bps (20%)
        &1000,    // long_lock_bonus_bps (10%)
        &1000,    // goal_completion_bonus (1000 points)
        &true,    // enabled
        &10,      // min_deposit_for_rewards (10 tokens)
        &60,      // action_cooldown_seconds (1 minute)
        &100_000, // max_daily_points
        &5000,    // max_streak_multiplier (50%)
    );

    // 2. Deposit multiple times to build streak
    // Streak starts at 1
    client.deposit_flexi(&user, &100);
    let rewards = client.get_user_rewards(&user);
    assert_eq!(rewards.current_streak, 1);
    assert_eq!(rewards.total_points, 1000); // 100 * 10

    // Advance time beyond cooldown but within streak window (7 days)
    env.ledger().with_mut(|li| li.timestamp += 70);

    // Streak 2
    client.deposit_flexi(&user, &100);
    let rewards = client.get_user_rewards(&user);
    assert_eq!(rewards.current_streak, 2);
    assert_eq!(rewards.total_points, 2000); // 1000 + 1000

    // Advance time (1 day)
    env.ledger().with_mut(|li| li.timestamp += 86400);

    // 3. Validate streak bonus (threshold is 3)
    client.deposit_flexi(&user, &100);
    let rewards = client.get_user_rewards(&user);
    assert_eq!(rewards.current_streak, 3);
    // Base: 1000, Bonus: 20% of 1000 = 200. Total added: 1200.
    // Cumulative: 2000 + 1200 = 3200
    assert_eq!(rewards.total_points, 3200);

    // 4. Complete goal
    let goal_name = Symbol::new(&env, "TestGoal");
    let target_amount = 500i128;
    let initial_deposit = 100i128;

    env.ledger().with_mut(|li| li.timestamp += 70);
    let goal_id = client.create_goal_save(&user, &goal_name, &target_amount, &initial_deposit);

    // Points for creation deposit (100 * 10 = 1000 + 20% streak bonus = 1200)
    // Cumulative: 3200 + 1200 = 4400
    let rewards = client.get_user_rewards(&user);
    assert_eq!(rewards.total_points, 4400);

    // Deposit to complete goal
    env.ledger().with_mut(|li| li.timestamp += 70);
    client.deposit_to_goal_save(&user, &goal_id, &400);

    // Points for 400 deposit (400 * 10 = 4000 + 20% streak bonus = 800) = 4800
    // Plus Goal Completion Bonus = 1000
    // Cumulative: 4400 + 4800 + 1000 = 10200
    let rewards = client.get_user_rewards(&user);
    assert_eq!(rewards.total_points, 10200);

    // 5. Redeem points
    client.redeem_points(&user, &2000);
    let rewards = client.get_user_rewards(&user);
    assert_eq!(rewards.total_points, 8200);

    // 7. Attempt abuse scenarios

    // - Zero deposit (should not award points)
    client.deposit_flexi(&user, &10); // 100 base + 20 bonus = 120
    let rewards_before = client.get_user_rewards(&user).total_points;
    let _ = client.try_deposit_flexi(&user, &0);
    let rewards_after = client.get_user_rewards(&user).total_points;
    assert_eq!(
        rewards_before, rewards_after,
        "Zero deposit should not award points"
    );

    // - Rapid-fire deposits (should skip points due to cooldown)
    env.ledger().with_mut(|li| li.timestamp += 70);
    client.deposit_flexi(&user, &100); // 1000 + 200 = 1200
    let rewards_before = client.get_user_rewards(&user).total_points;
    client.deposit_flexi(&user, &100); // Should be COOLING DOWN
    let rewards_after = client.get_user_rewards(&user).total_points;
    assert_eq!(
        rewards_before, rewards_after,
        "Points should not be awarded during cooldown"
    );

    // 8. Pause logic
    client.pause(&admin);
    let result = client.try_deposit_flexi(&user, &100);
    assert!(result.is_err(), "Deposit should fail when paused");
}

#[test]
fn test_rewards_invariants_and_abuse() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let admin_pk = BytesN::from_array(&env, &[1u8; 32]);
    client.initialize(&admin, &admin_pk);

    let user = Address::generate(&env);
    client.init_user(&user);

    client.init_rewards_config(&admin, &10, &0, &0, &0, &true, &0, &0, &1000, &10000);

    // Over-redemption
    client.deposit_flexi(&user, &50); // 500 points
    let result = client.try_redeem_points(&user, &1000);
    assert!(result.is_err(), "Redeem more than balance should fail");

    // Non-admin config update
    let prank_user = Address::generate(&env);
    let bad_config = client.get_rewards_config();
    let result = client.try_update_rewards_config(&prank_user, &bad_config);
    assert!(
        result.is_err(),
        "Non-admin should not be able to update config"
    );
}
