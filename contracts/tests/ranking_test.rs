#![cfg(test)]
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, Vec};
use Nestera::{NesteraContract, NesteraContractClient};

fn create_test_env() -> (Env, NesteraContractClient<'static>, Address, Vec<Address>) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let admin_pk = BytesN::from_array(&env, &[0u8; 32]);
    client.initialize(&admin, &admin_pk);

    // Create multiple test users
    let mut users = soroban_sdk::Vec::new(&env);
    for _ in 0..10 {
        let user = Address::generate(&env);
        client.init_user(&user);
        users.push_back(user);
    }

    (env, client, admin, users)
}

fn setup_rewards_config(client: &NesteraContractClient, admin: &Address) {
    client.init_rewards_config(
        admin, &10,        // points_per_token
        &0,         // streak_bonus_bps
        &0,         // long_lock_bonus_bps
        &0,         // goal_completion_bonus
        &true,      // enabled
        &100,       // min_deposit_for_rewards
        &0,         // action_cooldown_seconds (disabled for testing)
        &1_000_000, // max_daily_points (high limit)
        &10_000,    // max_streak_multiplier
    );
}

#[test]
fn test_get_top_users_empty() {
    let (_env, client, admin, _users) = create_test_env();
    setup_rewards_config(&client, &admin);

    let top_users = client.get_top_users(&5);
    assert_eq!(
        top_users.len(),
        0,
        "Should return empty list with no points"
    );
}

#[test]
fn test_get_top_users_basic() {
    let (_env, client, admin, users) = create_test_env();
    setup_rewards_config(&client, &admin);

    assert!(users.len() >= 4, "Need at least 4 users for test");

    // Give different amounts to users
    client.deposit_flexi(&users.get(0).unwrap().clone(), &1000); // 10,000 points
    client.deposit_flexi(&users.get(1).unwrap().clone(), &500); // 5,000 points
    client.deposit_flexi(&users.get(2).unwrap().clone(), &2000); // 20,000 points
    client.deposit_flexi(&users.get(3).unwrap().clone(), &1500); // 15,000 points

    let top_users = client.get_top_users(&10);
    assert_eq!(top_users.len(), 4, "Should return 4 users with points");

    // Check ordering (descending by points)
    let top1 = top_users.get(0).unwrap();
    let top2 = top_users.get(1).unwrap();
    let top3 = top_users.get(2).unwrap();
    let top4 = top_users.get(3).unwrap();

    assert_eq!(top1.0, users.get(2).unwrap(), "User 2 should be #1");
    assert_eq!(top1.1, 20_000, "Top user should have 20,000 points");

    assert_eq!(top2.0, users.get(3).unwrap(), "User 3 should be #2");
    assert_eq!(top2.1, 15_000, "Second user should have 15,000 points");

    assert_eq!(top3.0, users.get(0).unwrap(), "User 0 should be #3");
    assert_eq!(top3.1, 10_000, "Third user should have 10,000 points");

    assert_eq!(top4.0, users.get(1).unwrap(), "User 1 should be #4");
    assert_eq!(top4.1, 5_000, "Fourth user should have 5,000 points");
}

#[test]
fn test_get_top_users_limit() {
    let (_env, client, admin, users) = create_test_env();
    setup_rewards_config(&client, &admin);

    // Give points to 5 users
    for i in 0..5 {
        let user = users.get(i).unwrap();
        client.deposit_flexi(&user, &(((i + 1) * 100) as i128));
    }

    // Request only top 3
    let top_users = client.get_top_users(&3);
    assert_eq!(top_users.len(), 3, "Should return only 3 users");

    // Top 3 should be users with most deposits (indices 4, 3, 2)
    let top1 = top_users.get(0).unwrap();
    assert_eq!(top1.0, users.get(4).unwrap(), "User 4 should be #1");
    assert_eq!(top1.1, 5_000, "Should have 5,000 points");
}

#[test]
fn test_get_user_rank_not_ranked() {
    let (_env, client, admin, users) = create_test_env();
    setup_rewards_config(&client, &admin);

    assert!(!users.is_empty(), "Need at least 1 user for test");
    let rank = client.get_user_rank(&users.get(0).unwrap());
    assert_eq!(rank, 0, "User with no points should have rank 0");
}

#[test]
fn test_get_user_rank_basic() {
    let (_env, client, admin, users) = create_test_env();
    setup_rewards_config(&client, &admin);

    assert!(users.len() >= 4, "Need at least 4 users for test");

    // Give different amounts
    client.deposit_flexi(&users.get(0).unwrap().clone(), &1000); // 10,000 points - rank 3
    client.deposit_flexi(&users.get(1).unwrap().clone(), &500); // 5,000 points  - rank 4
    client.deposit_flexi(&users.get(2).unwrap().clone(), &2000); // 20,000 points - rank 1
    client.deposit_flexi(&users.get(3).unwrap().clone(), &1500); // 15,000 points - rank 2

    let rank0 = client.get_user_rank(&users.get(0).unwrap());
    let rank1 = client.get_user_rank(&users.get(1).unwrap());
    let rank2 = client.get_user_rank(&users.get(2).unwrap());
    let rank3 = client.get_user_rank(&users.get(3).unwrap());

    assert_eq!(rank0, 3, "User 0 should be rank 3");
    assert_eq!(rank1, 4, "User 1 should be rank 4");
    assert_eq!(rank2, 1, "User 2 should be rank 1");
    assert_eq!(rank3, 2, "User 3 should be rank 2");
}

#[test]
fn test_get_user_ranking_details() {
    let (_env, client, admin, users) = create_test_env();
    setup_rewards_config(&client, &admin);

    assert!(users.len() >= 2, "Need at least 2 users for test");

    // User with no points
    let details0 = client.get_user_ranking_details(&users.get(0).unwrap());
    assert!(details0.is_none(), "User with no points should return None");

    // Give points to some users
    client.deposit_flexi(&users.get(0).unwrap(), &1000); // 10,000 points
    client.deposit_flexi(&users.get(1).unwrap(), &2000); // 20,000 points

    let details0 = client.get_user_ranking_details(&users.get(0).unwrap());
    assert!(details0.is_some(), "User with points should have details");

    let (rank, points, total) = details0.unwrap();
    assert_eq!(rank, 2, "Should be rank 2");
    assert_eq!(points, 10_000, "Should have 10,000 points");
    assert_eq!(total, 2, "Should be 2 total ranked users");

    let details1 = client.get_user_ranking_details(&users.get(1).unwrap());
    let (rank1, points1, total1) = details1.unwrap();
    assert_eq!(rank1, 1, "Should be rank 1");
    assert_eq!(points1, 20_000, "Should have 20,000 points");
    assert_eq!(total1, 2, "Should be 2 total ranked users");
}

#[test]
fn test_ranking_with_ties() {
    let (_env, client, admin, users) = create_test_env();
    setup_rewards_config(&client, &admin);

    assert!(users.len() >= 3, "Need at least 3 users for test");

    // Give same amount to multiple users
    client.deposit_flexi(&users.get(0).unwrap(), &1000); // 10,000 points
    client.deposit_flexi(&users.get(1).unwrap(), &1000); // 10,000 points
    client.deposit_flexi(&users.get(2).unwrap(), &2000); // 20,000 points

    let top_users = client.get_top_users(&10);
    assert_eq!(top_users.len(), 3, "Should have 3 users");

    // First should be user with 20k points
    let top1 = top_users.get(0).unwrap();
    assert_eq!(top1.1, 20_000, "Top should have 20k points");

    // Next two should both have 10k points (order may vary)
    let top2 = top_users.get(1).unwrap();
    let top3 = top_users.get(2).unwrap();
    assert_eq!(top2.1, 10_000, "Second should have 10k points");
    assert_eq!(top3.1, 10_000, "Third should have 10k points");
}

#[test]
fn test_ranking_updates_on_new_deposits() {
    let (_env, client, admin, users) = create_test_env();
    setup_rewards_config(&client, &admin);

    assert!(users.len() >= 2, "Need at least 2 users for test");

    // Initial deposits
    client.deposit_flexi(&users.get(0).unwrap().clone(), &1000); // 10,000 points
    client.deposit_flexi(&users.get(1).unwrap().clone(), &500); // 5,000 points

    let rank0_before = client.get_user_rank(&users.get(0).unwrap());
    let rank1_before = client.get_user_rank(&users.get(1).unwrap());
    assert_eq!(rank0_before, 1, "User 0 should be rank 1 initially");
    assert_eq!(rank1_before, 2, "User 1 should be rank 2 initially");

    // User 1 makes big deposit to overtake user 0
    client.deposit_flexi(&users.get(1).unwrap(), &2000); // Total: 25,000 points

    let rank0_after = client.get_user_rank(&users.get(0).unwrap());
    let rank1_after = client.get_user_rank(&users.get(1).unwrap());
    assert_eq!(rank1_after, 1, "User 1 should be rank 1 after deposit");
    assert_eq!(rank0_after, 2, "User 0 should be rank 2 after deposit");
}

#[test]
fn test_large_user_set_safety() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let admin_pk = BytesN::from_array(&env, &[0u8; 32]);
    client.initialize(&admin, &admin_pk);
    setup_rewards_config(&client, &admin);

    // Create and fund many users
    for i in 0..50 {
        let user = Address::generate(&env);
        client.init_user(&user);
        client.deposit_flexi(&user, &(((i + 1) * 100) as i128));
    }

    // Should not panic with large user set
    let top_users = client.get_top_users(&20);
    assert!(top_users.len() <= 20, "Should respect limit");
    assert!(!top_users.is_empty(), "Should return some users");

    // Top user should have most points
    if !top_users.is_empty() {
        let top1 = top_users.get(0).unwrap();
        assert_eq!(top1.1, 50 * 100 * 10, "Top user should have highest points");
    }
}

#[test]
fn test_ranking_read_only() {
    let (_env, client, admin, users) = create_test_env();
    setup_rewards_config(&client, &admin);

    assert!(!users.is_empty(), "Need at least 1 user for test");

    client.deposit_flexi(&users.get(0).unwrap(), &1000);

    // Multiple calls should return consistent results (no state mutation)
    let top1 = client.get_top_users(&5);
    let top2 = client.get_top_users(&5);
    assert_eq!(top1.len(), top2.len(), "Should be consistent");

    let rank1 = client.get_user_rank(&users.get(0).unwrap());
    let rank2 = client.get_user_rank(&users.get(0).unwrap());
    assert_eq!(rank1, rank2, "Rank should be consistent");
}
