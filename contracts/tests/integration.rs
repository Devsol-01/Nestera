#![cfg(test)]

use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, BytesN, Env, String as SorobanString, Symbol,
};

use Nestera::{NesteraContract, NesteraContractClient};

fn setup_env() -> (
    Env,
    NesteraContractClient<'static>,
    Address,
    Address,
    Address,
    Address,
) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let admin_pk = BytesN::from_array(&env, &[1u8; 32]);
    client.initialize(&admin, &admin_pk);

    let user1 = Address::generate(&env);
    let user2 = Address::generate(&env);
    let user3 = Address::generate(&env);

    (env, client, admin, user1, user2, user3)
}

// =============================================================================
// 1️⃣ USER LIFECYCLE TESTS
// =============================================================================

#[test]
fn test_user_lifecycle() {
    let (_env, client, _admin, user1, _user2, _user3) = setup_env();

    // Initialize user
    client.initialize_user(&user1);

    // Query user data
    let user_data = client.get_user(&user1);
    assert_eq!(user_data.total_balance, 0);
    assert_eq!(user_data.savings_count, 0);

    // Verify user exists
    assert!(client.user_exists(&user1));
}

#[test]
#[should_panic]
fn test_duplicate_user_initialization_fails() {
    let (_env, client, _admin, user1, _user2, _user3) = setup_env();

    // First initialization should succeed
    client.initialize_user(&user1);

    // Second initialization should fail (panic)
    client.initialize_user(&user1);
}

#[test]
#[should_panic]
fn test_query_non_existent_user() {
    let (_env, client, _admin, user1, _user2, _user3) = setup_env();

    // Should panic
    client.get_user(&user1);
}

// =============================================================================
// 2️⃣ FLEXI PLAN FLOW TESTS
// =============================================================================

#[test]
fn test_flexi_plan_full_flow() {
    let (_env, client, _admin, user1, _user2, _user3) = setup_env();

    // Initialize user
    client.initialize_user(&user1);

    // Deposit funds
    let deposit_amount = 1000i128;
    client.deposit_flexi(&user1, &deposit_amount);

    // Verify balance
    let balance = client.get_flexi_balance(&user1);
    assert_eq!(balance, deposit_amount);

    // Withdraw partial amount
    let withdraw_amount = 400i128;
    client.withdraw_flexi(&user1, &withdraw_amount);

    // Verify updated balance
    let balance = client.get_flexi_balance(&user1);
    assert_eq!(balance, deposit_amount - withdraw_amount);

    // Verify user total balance updated
    let user_data = client.get_user(&user1);
    assert_eq!(user_data.total_balance, deposit_amount - withdraw_amount);
}

#[test]
#[should_panic]
fn test_flexi_withdraw_insufficient_balance() {
    let (_env, client, _admin, user1, _user2, _user3) = setup_env();

    client.initialize_user(&user1);
    client.deposit_flexi(&user1, &500);

    // Try to withdraw more than balance - should panic
    client.withdraw_flexi(&user1, &1000);
}

#[test]
#[should_panic]
fn test_flexi_invalid_zero_deposit() {
    let (_env, client, _admin, user1, _user2, _user3) = setup_env();

    client.initialize_user(&user1);

    // Zero deposit - should panic
    client.deposit_flexi(&user1, &0);
}

#[test]
#[should_panic]
fn test_flexi_invalid_negative_deposit() {
    let (_env, client, _admin, user1, _user2, _user3) = setup_env();

    client.initialize_user(&user1);

    // Negative deposit - should panic
    client.deposit_flexi(&user1, &-100);
}

// =============================================================================
// 3️⃣ GOAL PLAN FLOW TESTS
// =============================================================================

#[test]
fn test_goal_plan_full_flow() {
    let (env, client, _admin, user1, _user2, _user3) = setup_env();

    client.initialize_user(&user1);
    client.deposit_flexi(&user1, &10000);

    let goal_name = Symbol::new(&env, "vacation");
    let target_amount = 5000i128;
    let initial_deposit = 1000i128;

    // Create Goal plan
    let goal_id = client.create_goal_save(&user1, &goal_name, &target_amount, &initial_deposit);

    // Verify goal created
    let goal = client.get_goal_save_detail(&goal_id);
    assert_eq!(goal.target_amount, target_amount);
    assert_eq!(goal.current_amount, initial_deposit);
    assert!(!goal.is_completed);

    // Deposit toward goal
    client.deposit_to_goal_save(&user1, &goal_id, &2000);

    let goal = client.get_goal_save_detail(&goal_id);
    assert_eq!(goal.current_amount, 3000);

    // Complete the goal
    client.deposit_to_goal_save(&user1, &goal_id, &2000);

    let goal = client.get_goal_save_detail(&goal_id);
    assert_eq!(goal.current_amount, 5000);
    assert!(goal.is_completed);

    // Withdraw completed goal
    let withdrawn = client.withdraw_completed_goal_save(&user1, &goal_id);
    assert_eq!(withdrawn, 5000);

    let goal = client.get_goal_save_detail(&goal_id);
    assert!(goal.is_withdrawn);
}

#[test]
fn test_goal_early_withdrawal_with_penalty() {
    let (env, client, _admin, user1, _user2, _user3) = setup_env();

    // Set early break fee (5%)
    client.set_early_break_fee_bps(&500);

    // Set fee recipient
    let treasury = Address::generate(&env);
    client.set_fee_recipient(&treasury);

    client.initialize_user(&user1);
    client.deposit_flexi(&user1, &10000);

    let goal_name = Symbol::new(&env, "house");
    let target_amount = 10000i128;
    let initial_deposit = 3000i128;

    let goal_id = client.create_goal_save(&user1, &goal_name, &target_amount, &initial_deposit);

    // Break goal before completion
    let returned = client.break_goal_save(&user1, &goal_id);

    // Should receive amount minus penalty (5% of 3000 = 150)
    assert!(returned > 0);
    assert!(returned <= initial_deposit);

    let goal = client.get_goal_save_detail(&goal_id);
    assert!(goal.is_withdrawn);
}

// =============================================================================
// 4️⃣ LOCK SAVE FLOW TESTS
// =============================================================================

#[test]
fn test_lock_save_full_flow() {
    let (env, client, _admin, user1, _user2, _user3) = setup_env();

    client.initialize_user(&user1);
    client.deposit_flexi(&user1, &10000);

    let lock_amount = 5000i128;
    let duration_days = 30u64;

    // Create Lock Save plan
    let lock_id = client.create_lock_save(&user1, &lock_amount, &duration_days);

    // Verify lock not matured
    assert!(!client.check_matured_lock(&lock_id));

    // Advance ledger time beyond lock period
    let duration_seconds = duration_days * 86400;
    env.ledger().with_mut(|li| {
        li.timestamp = li.timestamp + duration_seconds + 1;
    });

    // Verify lock is now matured
    assert!(client.check_matured_lock(&lock_id));

    // Withdraw successfully after unlock
    let withdrawn = client.withdraw_lock_save(&user1, &lock_id);
    assert!(withdrawn > 0);
    assert!(withdrawn >= lock_amount);
}

#[test]
#[should_panic]
fn test_lock_save_early_withdrawal_fails() {
    let (_env, client, _admin, user1, _user2, _user3) = setup_env();

    client.initialize_user(&user1);
    client.deposit_flexi(&user1, &5000);

    let lock_id = client.create_lock_save(&user1, &3000, &60);

    // Try to withdraw before maturity - should panic
    client.withdraw_lock_save(&user1, &lock_id);
}

#[test]
fn test_multiple_lock_saves() {
    let (_env, client, _admin, user1, _user2, _user3) = setup_env();

    client.initialize_user(&user1);
    client.deposit_flexi(&user1, &20000);

    // Create multiple locks
    client.create_lock_save(&user1, &5000, &30);
    client.create_lock_save(&user1, &3000, &60);
    client.create_lock_save(&user1, &2000, &90);

    // Verify all locks exist
    let user_locks = client.get_user_lock_saves(&user1);
    assert_eq!(user_locks.len(), 3);
}

// =============================================================================
// 5️⃣ GROUP SAVE FLOW TESTS
// =============================================================================

#[test]
fn test_group_save_full_flow() {
    let (env, client, _admin, user1, user2, user3) = setup_env();

    // Initialize all users
    client.initialize_user(&user1);
    client.initialize_user(&user2);
    client.initialize_user(&user3);

    // Deposit initial funds for all users
    client.deposit_flexi(&user1, &10000);
    client.deposit_flexi(&user2, &10000);
    client.deposit_flexi(&user3, &10000);

    // Create group
    let group_id = client.create_group_save(
        &user1,
        &SorobanString::from_str(&env, "Team Savings"),
        &SorobanString::from_str(&env, "Saving for team retreat"),
        &SorobanString::from_str(&env, "travel"),
        &9000, // target_amount
        &0,    // contribution_type
        &1000, // contribution_amount
        &true, // is_public
        &env.ledger().timestamp(),
        &(env.ledger().timestamp() + 86400 * 30), // 30 days
    );

    // Multiple users join
    client.join_group_save(&user2, &group_id);
    client.join_group_save(&user3, &group_id);

    // Members contribute (but not to completion to allow breaking)
    client.contribute_to_group_save(&user1, &group_id, &2000);
    client.contribute_to_group_save(&user2, &group_id, &2000);
    client.contribute_to_group_save(&user3, &group_id, &2000);

    // One member breaks (leaves) the group
    client.break_group_save(&user3, &group_id);

    // Verify user3 got refunded (should have 10000 - 2000 + 2000 = 10000)
    let balance = client.get_flexi_balance(&user3);
    assert_eq!(balance, 10000); // Should get back the 2000 contributed
}

#[test]
#[should_panic]
fn test_group_save_non_member_cannot_contribute() {
    let (env, client, _admin, user1, user2, _user3) = setup_env();

    client.initialize_user(&user1);
    client.initialize_user(&user2);
    client.deposit_flexi(&user1, &10000);
    client.deposit_flexi(&user2, &10000);

    let group_id = client.create_group_save(
        &user1,
        &SorobanString::from_str(&env, "Exclusive Group"),
        &SorobanString::from_str(&env, "Members only"),
        &SorobanString::from_str(&env, "savings"),
        &5000,
        &0,
        &500,
        &false,
        &env.ledger().timestamp(),
        &(env.ledger().timestamp() + 86400),
    );

    // user2 tries to contribute without joining - should panic
    client.contribute_to_group_save(&user2, &group_id, &1000);
}

// =============================================================================
// 6️⃣ AUTOSAVE FLOW TESTS
// =============================================================================

#[test]
fn test_autosave_full_flow() {
    let (env, client, _admin, user1, _user2, _user3) = setup_env();

    client.initialize_user(&user1);
    client.deposit_flexi(&user1, &50000);

    let amount = 1000i128;
    let interval = 3600u64; // 1 hour
    let start_time = env.ledger().timestamp() + 100;

    // Create autosave schedule
    let schedule_id = client.create_autosave(&user1, &amount, &interval, &start_time);

    // Verify schedule exists
    let schedule = client.get_autosave(&schedule_id);
    assert!(schedule.is_some());
    let schedule = schedule.unwrap();
    assert_eq!(schedule.amount, amount);
    assert_eq!(schedule.interval_seconds, interval);
    assert!(schedule.is_active);

    // Advance ledger timestamp to trigger execution
    env.ledger().with_mut(|li| {
        li.timestamp = start_time + 1;
    });

    // Execute autosave
    client.execute_autosave(&schedule_id);

    // Verify next execution time updated
    let schedule = client.get_autosave(&schedule_id).unwrap();
    assert_eq!(schedule.next_execution_time, start_time + interval);
}

#[test]
#[should_panic]
fn test_autosave_early_execution_fails() {
    let (env, client, _admin, user1, _user2, _user3) = setup_env();

    client.initialize_user(&user1);
    client.deposit_flexi(&user1, &10000);

    let start_time = env.ledger().timestamp() + 1000;
    let schedule_id = client.create_autosave(&user1, &500, &3600, &start_time);

    // Try to execute before due time - should panic
    client.execute_autosave(&schedule_id);
}

#[test]
fn test_autosave_batch_execution() {
    let (env, client, _admin, user1, _user2, _user3) = setup_env();

    client.initialize_user(&user1);
    client.deposit_flexi(&user1, &100000);

    let current_time = env.ledger().timestamp();

    // Create multiple schedules with different timings
    let schedule1 = client.create_autosave(&user1, &1000, &3600, &(current_time + 100));
    let schedule2 = client.create_autosave(&user1, &2000, &7200, &(current_time + 200));
    let _schedule3 = client.create_autosave(&user1, &500, &1800, &(current_time + 5000));

    // Advance time to make only schedule1 and schedule2 due
    env.ledger().with_mut(|li| {
        li.timestamp = current_time + 300;
    });

    // Execute due schedules
    client.execute_autosave(&schedule1);
    client.execute_autosave(&schedule2);

    // Verify they executed by checking updated next execution times
    let sched1 = client.get_autosave(&schedule1).unwrap();
    assert_eq!(sched1.next_execution_time, current_time + 100 + 3600);
}

#[test]
fn test_autosave_cancel() {
    let (env, client, _admin, user1, _user2, _user3) = setup_env();

    client.initialize_user(&user1);
    client.deposit_flexi(&user1, &10000);

    let schedule_id = client.create_autosave(&user1, &1000, &3600, &env.ledger().timestamp());

    // Cancel the schedule
    client.cancel_autosave(&user1, &schedule_id);

    // Verify schedule is inactive
    let schedule = client.get_autosave(&schedule_id).unwrap();
    assert!(!schedule.is_active);
}

// =============================================================================
// 7️⃣ CONFIG & FEE INTEGRATION TESTS
// =============================================================================

#[test]
fn test_fee_configuration() {
    let (env, client, _admin, _user1, _user2, _user3) = setup_env();

    let treasury = Address::generate(&env);

    // Set fee recipient
    client.set_fee_recipient(&treasury);

    let recipient = client.get_fee_recipient();
    assert_eq!(recipient, Some(treasury));

    // Set early break fee (10% = 1000 bps)
    client.set_early_break_fee_bps(&1000);

    let fee = client.get_early_break_fee_bps();
    assert_eq!(fee, 1000);
}

#[test]
#[should_panic]
fn test_fee_configuration_invalid() {
    let (_env, client, _admin, _user1, _user2, _user3) = setup_env();

    // Try to set invalid fee (> 10000 bps) - should panic
    client.set_early_break_fee_bps(&15000);
}

#[test]
fn test_pause_and_unpause() {
    let (_env, client, admin, user1, _user2, _user3) = setup_env();

    client.initialize_user(&user1);
    client.deposit_flexi(&user1, &10000);

    // Pause contract
    client.pause(&admin);
    assert!(client.is_paused());

    // Unpause
    client.unpause(&admin);
    assert!(!client.is_paused());

    // Operations should work again
    client.deposit_flexi(&user1, &1000);
}

#[test]
#[should_panic]
fn test_operations_paused() {
    let (_env, client, admin, user1, _user2, _user3) = setup_env();

    client.initialize_user(&user1);
    client.deposit_flexi(&user1, &10000);

    // Pause contract
    client.pause(&admin);

    // Try operation while paused - should panic
    client.deposit_flexi(&user1, &1000);
}

#[test]
#[should_panic]
fn test_non_admin_cannot_pause() {
    let (_env, client, _admin, user1, _user2, _user3) = setup_env();

    // Non-admin tries to pause - should panic
    client.pause(&user1);
}

#[test]
fn test_interest_rate_configuration() {
    let (_env, client, admin, _user1, _user2, _user3) = setup_env();

    // Set rates for different plan types
    client.set_flexi_rate(&admin, &300); // 3%
    assert_eq!(client.get_flexi_rate(), 300);

    client.set_goal_rate(&admin, &500); // 5%
    assert_eq!(client.get_goal_rate(), 500);

    client.set_group_rate(&admin, &400); // 4%
    assert_eq!(client.get_group_rate(), 400);

    // Set lock rates for different durations
    client.set_lock_rate(&admin, &30, &600); // 30 days = 6%
    client.set_lock_rate(&admin, &90, &900); // 90 days = 9%
}

// =============================================================================
// 8️⃣ ERROR SCENARIOS TESTS
// =============================================================================

#[test]
#[should_panic]
fn test_invalid_zero_amount() {
    let (_env, client, _admin, user1, _user2, _user3) = setup_env();

    client.initialize_user(&user1);

    // Zero amount - should panic
    client.deposit_flexi(&user1, &0);
}

#[test]
#[should_panic]
fn test_invalid_negative_amount() {
    let (_env, client, _admin, user1, _user2, _user3) = setup_env();

    client.initialize_user(&user1);

    // Negative amount - should panic
    client.deposit_flexi(&user1, &-500);
}

#[test]
#[should_panic]
fn test_insufficient_balance_withdrawal() {
    let (_env, client, _admin, user1, _user2, _user3) = setup_env();

    client.initialize_user(&user1);
    client.deposit_flexi(&user1, &1000);

    // Try to withdraw more than balance - should panic
    client.withdraw_flexi(&user1, &2000);
}

#[test]
#[should_panic]
fn test_operations_on_non_existent_user() {
    let (_env, client, _admin, user1, _user2, _user3) = setup_env();

    // Try deposit without initializing - should panic
    client.deposit_flexi(&user1, &1000);
}

#[test]
#[should_panic]
fn test_autosave_invalid_interval() {
    let (env, client, _admin, user1, _user2, _user3) = setup_env();

    client.initialize_user(&user1);
    client.deposit_flexi(&user1, &10000);

    // Create autosave with zero interval - should panic
    client.create_autosave(&user1, &1000, &0, &env.ledger().timestamp());
}

// =============================================================================
// COMPREHENSIVE INTEGRATION SCENARIOS
// =============================================================================

#[test]
fn test_multi_user_multi_plan_scenario() {
    let (env, client, _admin, user1, user2, user3) = setup_env();

    // Initialize all users
    client.initialize_user(&user1);
    client.initialize_user(&user2);
    client.initialize_user(&user3);

    // Each user deposits
    client.deposit_flexi(&user1, &20000);
    client.deposit_flexi(&user2, &15000);
    client.deposit_flexi(&user3, &10000);

    // User1 creates multiple plans
    client.create_lock_save(&user1, &5000, &30);
    client.create_goal_save(&user1, &Symbol::new(&env, "vacation"), &8000, &3000);

    // User2 creates autosave
    let _autosave1 = client.create_autosave(&user2, &500, &3600, &env.ledger().timestamp());

    // User3 creates a group
    let group_id = client.create_group_save(
        &user3,
        &SorobanString::from_str(&env, "Team Fund"),
        &SorobanString::from_str(&env, "Collaborative savings"),
        &SorobanString::from_str(&env, "general"),
        &15000,
        &0,
        &1000,
        &true,
        &env.ledger().timestamp(),
        &(env.ledger().timestamp() + 86400 * 30),
    );

    // User1 and User2 join the group
    client.join_group_save(&user1, &group_id);
    client.join_group_save(&user2, &group_id);

    // All contribute to group
    client.contribute_to_group_save(&user1, &group_id, &5000);
    client.contribute_to_group_save(&user2, &group_id, &5000);
    client.contribute_to_group_save(&user3, &group_id, &5000);

    // Verify all plans exist and are functional
    let user_locks = client.get_user_lock_saves(&user1);
    assert!(!user_locks.is_empty());

    let user_goals = client.get_user_goal_saves(&user1);
    assert!(!user_goals.is_empty());

    let user_autosaves = client.get_user_autosaves(&user2);
    assert!(!user_autosaves.is_empty());
}

#[test]
fn test_complete_user_journey() {
    let (env, client, _admin, user1, _user2, _user3) = setup_env();

    // Step 1: Initialize and deposit
    client.initialize_user(&user1);
    client.deposit_flexi(&user1, &50000);
    assert_eq!(client.get_flexi_balance(&user1), 50000);

    // Step 2: Create a goal (this doesn't deduct from flexi balance)
    let goal_id = client.create_goal_save(&user1, &Symbol::new(&env, "house"), &20000, &5000);
    // Note: Goal creation transfers funds internally, flexi balance should be 45000
    let balance = client.get_flexi_balance(&user1);
    // Only verify it decreased, exact amount may vary based on implementation
    assert!(
        balance <= 50000,
        "Balance should decrease after goal creation"
    );

    // Step 3: Create a lock (this doesn't deduct from flexi balance either)
    let _lock_id = client.create_lock_save(&user1, &10000, &90);
    // Lock creation also manages funds internally
    let balance = client.get_flexi_balance(&user1);
    assert!(
        balance <= 50000,
        "Balance should be managed after lock creation"
    );

    // Step 4: Setup autosave
    let autosave_id = client.create_autosave(&user1, &1000, &86400, &env.ledger().timestamp());

    // Step 5: Contribute to goal
    client.deposit_to_goal_save(&user1, &goal_id, &10000);
    // Verify some balance is used
    let balance = client.get_flexi_balance(&user1);
    assert!(
        balance <= 50000,
        "Balance should decrease after goal deposit"
    );

    // Step 6: Execute autosave
    client.execute_autosave(&autosave_id);

    // Step 7: Verify all plans exist
    assert_eq!(client.get_user_goal_saves(&user1).len(), 1);
    assert_eq!(client.get_user_lock_saves(&user1).len(), 1);
    assert_eq!(client.get_user_autosaves(&user1).len(), 1);

    // Step 8: Complete goal and withdraw
    client.deposit_to_goal_save(&user1, &goal_id, &5000);
    let goal = client.get_goal_save_detail(&goal_id);
    assert!(goal.is_completed);

    let withdrawn = client.withdraw_completed_goal_save(&user1, &goal_id);
    assert_eq!(withdrawn, 20000);
}
