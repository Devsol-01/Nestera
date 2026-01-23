#![cfg(test)]
extern crate std;

use super::*;
use soroban_sdk::{symbol_short, testutils::{Address as _, Ledger}, Address, Env};

#[test]
fn test_initialize_sets_admin() {
    let env = Env::default();
    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    
    // Mock authentication for the admin
    env.mock_all_auths();
    
    // Initialize the contract with admin
    client.initialize(&admin);
    
    // Verify admin was set correctly
    let stored_admin = client.get_admin();
    assert_eq!(stored_admin, admin);
}

#[test]
#[should_panic(expected = "Admin already initialized")]
fn test_initialize_twice_fails() {
    let env = Env::default();
    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    
    // Mock authentication
    env.mock_all_auths();
    
    // Initialize the contract - should succeed
    client.initialize(&admin);
    
    // Try to initialize again - should panic
    client.initialize(&admin);
}

#[test]
fn test_update_admin_by_current_admin_succeeds() {
    let env = Env::default();
    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    
    // Mock authentication
    env.mock_all_auths();
    
    // Initialize with first admin
    client.initialize(&admin);
    
    // Update to new admin
    client.update_admin(&new_admin);
    
    // Verify admin was updated
    let stored_admin = client.get_admin();
    assert_eq!(stored_admin, new_admin);
}

#[test]
fn test_update_admin_requires_current_admin_auth() {
    let env = Env::default();
    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    
    // Initialize with admin
    env.mock_all_auths();
    client.initialize(&admin);
    
    // Clear previous auths and test update_admin
    env.mock_all_auths_allowing_non_root_auth();
    client.update_admin(&new_admin);
    
    // Verify that both admin and new_admin were required to authorize
    // We expect 2 authorizations: one from current admin, one from new admin
    assert_eq!(env.auths().len(), 2);
    
    // Verify the first auth is from the current admin
    let auth_addresses: std::vec::Vec<_> = env.auths()
        .iter()
        .map(|(addr, _)| addr.clone())
        .collect();
    
    assert!(auth_addresses.contains(&admin));
    assert!(auth_addresses.contains(&new_admin));
}

#[test]
#[should_panic(expected = "Admin not initialized")]
fn test_get_admin_fails_when_not_initialized() {
    let env = Env::default();
    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);
    
    // Try to get admin without initializing - should panic
    client.get_admin();
}

#[test]
#[should_panic(expected = "Admin not initialized")]
fn test_update_admin_fails_when_not_initialized() {
    let env = Env::default();
    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);
    
    let new_admin = Address::generate(&env);
    
    // Mock authentication
    env.mock_all_auths();
    
    // Try to update admin without initializing - should panic
    client.update_admin(&new_admin);
}

#[test]
fn test_user_instantiation() {
    let user = User {
        total_balance: 1_000_000,
        savings_count: 3,
    };

    assert_eq!(user.total_balance, 1_000_000);
    assert_eq!(user.savings_count, 3);
}

#[test]
fn test_flexi_savings_plan() {
    let plan = SavingsPlan {
        plan_id: 1,
        plan_type: PlanType::Flexi,
        balance: 500_000,
        start_time: 1000000,
        last_deposit: 1000100,
        last_withdraw: 0,
        interest_rate: 500, // 5.00% APY
        is_completed: false,
        is_withdrawn: false,
    };

    assert_eq!(plan.plan_id, 1);
    assert_eq!(plan.plan_type, PlanType::Flexi);
    assert_eq!(plan.balance, 500_000);
    assert!(!plan.is_completed);
}

#[test]
fn test_lock_savings_plan() {
    let locked_until = 2000000;
    let plan = SavingsPlan {
        plan_id: 2,
        plan_type: PlanType::Lock(locked_until),
        balance: 1_000_000,
        start_time: 1000000,
        last_deposit: 1000000,
        last_withdraw: 0,
        interest_rate: 800,
        is_completed: false,
        is_withdrawn: false,
    };

    assert_eq!(plan.plan_id, 2);
    match plan.plan_type {
        PlanType::Lock(until) => assert_eq!(until, locked_until),
        _ => panic!("Expected Lock plan type"),
    }
}

#[test]
fn test_goal_savings_plan() {
    let plan = SavingsPlan {
        plan_id: 3,
        plan_type: PlanType::Goal(
            symbol_short!("education"),
            5_000_000,
            1u32, // e.g. 1 = weekly
        ),
        balance: 2_000_000,
        start_time: 1000000,
        last_deposit: 1500000,
        last_withdraw: 0,
        interest_rate: 600,
        is_completed: false,
        is_withdrawn: false,
    };

    assert_eq!(plan.plan_id, 3);
    match plan.plan_type {
        PlanType::Goal(category, target_amount, contribution_type) => {
            assert_eq!(category, symbol_short!("education"));
            assert_eq!(target_amount, 5_000_000);
            assert_eq!(contribution_type, 1u32);
        }
        _ => panic!("Expected Goal plan type"),
    }
}

#[test]
fn test_group_savings_plan() {
    let plan = SavingsPlan {
        plan_id: 4,
        plan_type: PlanType::Group(101, true, 2u32, 10_000_000),
        balance: 3_000_000,
        start_time: 1000000,
        last_deposit: 1600000,
        last_withdraw: 0,
        interest_rate: 700,
        is_completed: false,
        is_withdrawn: false,
    };

    assert_eq!(plan.plan_id, 4);
    match plan.plan_type {
        PlanType::Group(group_id, is_public, contribution_type, target_amount) => {
            assert_eq!(group_id, 101);
            assert!(is_public);
            assert_eq!(contribution_type, 2u32);
            assert_eq!(target_amount, 10_000_000);
        }
        _ => panic!("Expected Group plan type"),
    }
}

#[test]
fn test_data_key_admin() {
    let key = DataKey::Admin;
    assert_eq!(key, DataKey::Admin);
}

#[test]
fn test_data_key_user() {
    let env = Env::default();
    let user_address = Address::generate(&env);
    let key = DataKey::User(user_address.clone());

    match key {
        DataKey::User(addr) => assert_eq!(addr, user_address),
        _ => panic!("Expected User data key"),
    }
}

#[test]
fn test_data_key_savings_plan() {
    let env = Env::default();
    let user_address = Address::generate(&env);
    let plan_id = 42;
    let key = DataKey::SavingsPlan(user_address.clone(), plan_id);

    match key {
        DataKey::SavingsPlan(addr, id) => {
            assert_eq!(addr, user_address);
            assert_eq!(id, plan_id);
        }
        _ => panic!("Expected SavingsPlan data key"),
    }
}

#[test]
fn test_xdr_compatibility_user() {
    let env = Env::default();
    let contract_id = env.register(NesteraContract, ());

    let user = User {
        total_balance: 1_500_000,
        savings_count: 5,
    };

    let key = symbol_short!("testuser");
    env.as_contract(&contract_id, || {
        env.storage().instance().set(&key, &user);
        let retrieved_user: User = env.storage().instance().get(&key).unwrap();
        assert_eq!(user, retrieved_user);
    });
}

#[test]
fn test_xdr_compatibility_savings_plan() {
    let env = Env::default();
    let contract_id = env.register(NesteraContract, ());

    let plan = SavingsPlan {
        plan_id: 1,
        plan_type: PlanType::Flexi,
        balance: 750_000,
        start_time: 1000000,
        last_deposit: 1100000,
        last_withdraw: 1050000,
        interest_rate: 550,
        is_completed: false,
        is_withdrawn: false,
    };

    let key = symbol_short!("testplan");
    env.as_contract(&contract_id, || {
        env.storage().instance().set(&key, &plan);
        let retrieved_plan: SavingsPlan = env.storage().instance().get(&key).unwrap();
        assert_eq!(plan, retrieved_plan);
    });
}

#[test]
fn test_xdr_compatibility_all_plan_types() {
    let env = Env::default();
    let contract_id = env.register(NesteraContract, ());

    env.as_contract(&contract_id, || {
        // Test Flexi
        let flexi_plan = SavingsPlan {
            plan_id: 0,
            plan_type: PlanType::Flexi,
            balance: 1_000_000,
            start_time: 1000000,
            last_deposit: 1100000,
            last_withdraw: 0,
            interest_rate: 500,
            is_completed: false,
            is_withdrawn: false,
        };
        env.storage().instance().set(&0u32, &flexi_plan);
        let retrieved: SavingsPlan = env.storage().instance().get(&0u32).unwrap();
        assert_eq!(flexi_plan, retrieved);

        // Test Lock
        let lock_plan = SavingsPlan {
            plan_id: 1,
            plan_type: PlanType::Lock(2000000),
            balance: 1_000_000,
            start_time: 1000000,
            last_deposit: 1100000,
            last_withdraw: 0,
            interest_rate: 500,
            is_completed: false,
            is_withdrawn: false,
        };
        env.storage().instance().set(&1u32, &lock_plan);
        let retrieved: SavingsPlan = env.storage().instance().get(&1u32).unwrap();
        assert_eq!(lock_plan, retrieved);

        // Test Goal
        let goal_plan = SavingsPlan {
            plan_id: 2,
            plan_type: PlanType::Goal(symbol_short!("vacation"), 3_000_000, 1u32),
            balance: 1_000_000,
            start_time: 1000000,
            last_deposit: 1100000,
            last_withdraw: 0,
            interest_rate: 500,
            is_completed: false,
            is_withdrawn: false,
        };
        env.storage().instance().set(&2u32, &goal_plan);
        let retrieved: SavingsPlan = env.storage().instance().get(&2u32).unwrap();
        assert_eq!(goal_plan, retrieved);

        // Test Group
        let group_plan = SavingsPlan {
            plan_id: 3,
            plan_type: PlanType::Group(200, false, 3u32, 8_000_000),
            balance: 1_000_000,
            start_time: 1000000,
            last_deposit: 1100000,
            last_withdraw: 0,
            interest_rate: 500,
            is_completed: false,
            is_withdrawn: false,
        };
        env.storage().instance().set(&3u32, &group_plan);
        let retrieved: SavingsPlan = env.storage().instance().get(&3u32).unwrap();
        assert_eq!(group_plan, retrieved);
    });
}

#[test]
fn test_completed_plan() {
    let plan = SavingsPlan {
        plan_id: 5,
        plan_type: PlanType::Goal(symbol_short!("house"), 10_000_000, 2u32),
        balance: 10_000_000,
        start_time: 1000000,
        last_deposit: 2000000,
        last_withdraw: 0,
        interest_rate: 650,
        is_completed: true,
        is_withdrawn: false,
    };

    assert!(plan.is_completed);
    assert_eq!(plan.balance, 10_000_000);
}

#[test]
fn test_plan_type_patterns() {
    // Test that we can extract values from each plan type variant
    let lock_plan = PlanType::Lock(1234567);
    if let PlanType::Lock(timestamp) = lock_plan {
        assert_eq!(timestamp, 1234567);
    }

    let goal_plan = PlanType::Goal(symbol_short!("car"), 2_000_000, 3u32);
    if let PlanType::Goal(cat, amount, contrib) = goal_plan {
        assert_eq!(cat, symbol_short!("car"));
        assert_eq!(amount, 2_000_000);
        assert_eq!(contrib, 3u32);
    }

    let group_plan = PlanType::Group(999, true, 1u32, 5_000_000);
    if let PlanType::Group(id, public, contrib, amount) = group_plan {
        assert_eq!(id, 999);
        assert!(public);
        assert_eq!(contrib, 1u32);
        assert_eq!(amount, 5_000_000);
    }
}

// ========== User Initialization Tests ==========

#[test]
fn test_initialize_user_success() {
    let env = Env::default();
    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);

    let user = Address::generate(&env);

    env.mock_all_auths();

    // Initialize user should succeed
    let result = client.initialize_user(&user);
    assert_eq!(result, ());

    // Verify user exists
    assert!(client.user_exists(&user));
}

#[test]
fn test_initialize_user_duplicate_fails() {
    let env = Env::default();
    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);

    let user = Address::generate(&env);

    env.mock_all_auths();

    // First initialization should succeed
    client.initialize_user(&user);

    // Second initialization should fail with UserAlreadyExists
    let result = client.try_initialize_user(&user);
    assert_eq!(result, Err(Ok(SavingsError::UserAlreadyExists)));
}

#[test]
fn test_get_user_not_found() {
    let env = Env::default();
    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);

    let user = Address::generate(&env);

    // get_user for non-existent user should return UserNotFound
    let result = client.try_get_user(&user);
    assert_eq!(result, Err(Ok(SavingsError::UserNotFound)));
}

#[test]
fn test_get_user_success() {
    let env = Env::default();
    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);

    let user = Address::generate(&env);

    env.mock_all_auths();

    // Initialize user
    client.initialize_user(&user);

    // get_user should return user data with default values
    let user_data = client.get_user(&user);
    assert_eq!(user_data.total_balance, 0);
    assert_eq!(user_data.savings_count, 0);
}

#[test]
fn test_user_exists_false_for_new_user() {
    let env = Env::default();
    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);

    let user = Address::generate(&env);

    // user_exists should return false for non-existent user
    assert!(!client.user_exists(&user));
}

#[test]
fn test_initialize_user_requires_auth() {
    let env = Env::default();
    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);

    let user = Address::generate(&env);

    env.mock_all_auths_allowing_non_root_auth();

    // Initialize user
    client.initialize_user(&user);

    // Verify that the user was required to authorize
    let auths = env.auths();
    assert_eq!(auths.len(), 1);
    let (auth_addr, _) = &auths[0];
    assert_eq!(auth_addr, &user);
}
