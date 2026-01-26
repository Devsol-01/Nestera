#![cfg(test)]
extern crate std;

use crate::{
    flexi, DataKey, MintPayload, NesteraContract, NesteraContractClient, PlanType, SavingsError,
    SavingsPlan, User,
};
use ed25519_dalek::{Signer, SigningKey};
use soroban_sdk::testutils::{Address as _, Ledger, LedgerInfo};
use soroban_sdk::{symbol_short, xdr::ToXdr, Address, Bytes, BytesN, Env, String};
// use std::format;

/// Helper function to create a test environment and contract client
fn setup_test_env() -> (Env, NesteraContractClient<'static>) {
    let env = Env::default();
    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);
    (env, client)
}

/// Helper function to generate an Ed25519 keypair for testing
/// Returns (signing_key, public_key_bytes)
fn generate_keypair(env: &Env) -> (SigningKey, BytesN<32>) {
    // Create a deterministic signing key for testing
    let secret_bytes: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    let signing_key = SigningKey::from_bytes(&secret_bytes);

    // Get the public key bytes
    let public_key = signing_key.verifying_key();
    let public_key_bytes: BytesN<32> = BytesN::from_array(env, &public_key.to_bytes());

    (signing_key, public_key_bytes)
}

fn test_address(id: u8) -> Address {
    let env = Env::default();

    // create a 32-byte array for the test
    let mut b = [0u8; 32];
    b[0] = id; // just make each test address unique

    // convert BytesN to Bytes
    let bytes = Bytes::from_array(&env, &b);

    // create Address from Bytes (no Env argument!)
    Address::from_string_bytes(&bytes)
}

/// Generate a second keypair (attacker) for testing wrong signer scenarios
fn generate_attacker_keypair(env: &Env) -> (SigningKey, BytesN<32>) {
    let secret_bytes: [u8; 32] = [
        99, 98, 97, 96, 95, 94, 93, 92, 91, 90, 89, 88, 87, 86, 85, 84, 83, 82, 81, 80, 79, 78, 77,
        76, 75, 74, 73, 72, 71, 70, 69, 68,
    ];
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let public_key = signing_key.verifying_key();
    let public_key_bytes: BytesN<32> = BytesN::from_array(env, &public_key.to_bytes());

    (signing_key, public_key_bytes)
}

/// Helper to sign a payload with the admin's secret key
fn sign_payload(env: &Env, signing_key: &SigningKey, payload: &MintPayload) -> BytesN<64> {
    // Serialize payload to XDR (same as contract does)
    let payload_bytes: Bytes = payload.to_xdr(env);

    // Convert Bytes to Vec<u8> for signing
    let len = payload_bytes.len() as usize;
    let mut payload_slice: std::vec::Vec<u8> = std::vec![0u8; len];
    payload_bytes.copy_into_slice(&mut payload_slice);

    // Sign with ed25519_dalek
    let signature = signing_key.sign(&payload_slice);

    // Convert signature to BytesN<64>
    BytesN::from_array(env, &signature.to_bytes())
}

/// Helper to set the ledger timestamp
fn set_ledger_timestamp(env: &Env, timestamp: u64) {
    env.ledger().set(LedgerInfo {
        timestamp,
        protocol_version: 23,
        sequence_number: 100,
        network_id: [0u8; 32],
        base_reserve: 10,
        min_temp_entry_ttl: 10,
        min_persistent_entry_ttl: 10,
        max_entry_ttl: 3110400,
    });
}

// =============================================================================
// Initialization Tests
// =============================================================================

#[test]
fn test_initialize_success() {
    let (env, client) = setup_test_env();
    let (_, admin_public_key) = generate_keypair(&env);

    // Should not be initialized yet
    assert!(!client.is_initialized());

    // Initialize the contract
    client.initialize(&admin_public_key);

    // Should be initialized now
    assert!(client.is_initialized());

    // Verify the stored public key matches
    let stored_key = client.get_admin_public_key();
    assert_eq!(stored_key, admin_public_key);
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn test_initialize_already_initialized() {
    let (env, client) = setup_test_env();
    let (_, admin_public_key) = generate_keypair(&env);

    // Initialize once
    client.initialize(&admin_public_key);

    // Try to initialize again - should panic with AlreadyInitialized (error code 1)
    client.initialize(&admin_public_key);
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")]
fn test_get_admin_public_key_not_initialized() {
    let (_, client) = setup_test_env();

    // Should panic with NotInitialized (error code 2)
    client.get_admin_public_key();
}

// =============================================================================
// Signature Verification Tests
// =============================================================================

#[test]
fn test_verify_signature_success() {
    let (env, client) = setup_test_env();
    let (signing_key, admin_public_key) = generate_keypair(&env);

    // Initialize with admin public key
    client.initialize(&admin_public_key);

    // Set ledger timestamp
    let current_time = 1000u64;
    set_ledger_timestamp(&env, current_time);

    // Create a mint payload
    let user = Address::generate(&env);
    let payload = MintPayload {
        user: user.clone(),
        amount: 100_i128,
        timestamp: current_time,
        expiry_duration: 3600, // 1 hour validity
    };

    // Sign the payload with admin's secret key
    let signature = sign_payload(&env, &signing_key, &payload);

    // Verify should succeed and return true
    assert!(client.verify_signature(&payload, &signature));
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")]
fn test_verify_signature_not_initialized() {
    let (env, client) = setup_test_env();
    let (signing_key, _) = generate_keypair(&env);

    let user = Address::generate(&env);
    let payload = MintPayload {
        user,
        amount: 100_i128,
        timestamp: 1000,
        expiry_duration: 3600,
    };

    let signature = sign_payload(&env, &signing_key, &payload);

    // Should panic because contract is not initialized
    client.verify_signature(&payload, &signature);
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn test_verify_signature_expired() {
    let (env, client) = setup_test_env();
    let (signing_key, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

    // Create a payload that was signed in the past
    let user = Address::generate(&env);
    let payload = MintPayload {
        user,
        amount: 100_i128,
        timestamp: 1000,
        expiry_duration: 3600, // Expires at 4600
    };

    let signature = sign_payload(&env, &signing_key, &payload);

    // Set ledger timestamp to after expiry
    set_ledger_timestamp(&env, 5000);

    // Should panic with SignatureExpired (error code 4)
    client.verify_signature(&payload, &signature);
}

#[test]
#[should_panic]
fn test_verify_signature_invalid_signature() {
    let (env, client) = setup_test_env();
    let (signing_key, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

    let current_time = 1000u64;
    set_ledger_timestamp(&env, current_time);

    let user = Address::generate(&env);
    let payload = MintPayload {
        user,
        amount: 100_i128,
        timestamp: current_time,
        expiry_duration: 3600,
    };

    // Sign with admin key
    let signature = sign_payload(&env, &signing_key, &payload);

    // Modify the payload after signing (tamper with it)
    let tampered_payload = MintPayload {
        user: Address::generate(&env), // Different user!
        amount: 100_i128,
        timestamp: current_time,
        expiry_duration: 3600,
    };

    // Should panic because signature doesn't match tampered payload
    client.verify_signature(&tampered_payload, &signature);
}

#[test]
#[should_panic]
fn test_verify_signature_wrong_signer() {
    let (env, client) = setup_test_env();
    let (_, admin_public_key) = generate_keypair(&env);
    let (attacker_signing_key, _) = generate_attacker_keypair(&env);

    client.initialize(&admin_public_key);

    let current_time = 1000u64;
    set_ledger_timestamp(&env, current_time);

    let user = Address::generate(&env);
    let payload = MintPayload {
        user,
        amount: 100_i128,
        timestamp: current_time,
        expiry_duration: 3600,
    };

    // Sign with attacker's key instead of admin's key
    let bad_signature = sign_payload(&env, &attacker_signing_key, &payload);

    // Should panic because signature is from wrong key
    client.verify_signature(&payload, &bad_signature);
}

// =============================================================================
// Mint Tests
// =============================================================================

#[test]
fn test_mint_success() {
    let (env, client) = setup_test_env();
    let (signing_key, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

    let current_time = 1000u64;
    set_ledger_timestamp(&env, current_time);

    let user = Address::generate(&env);
    let mint_amount = 500_i128;

    let payload = MintPayload {
        user: user.clone(),
        amount: mint_amount,
        timestamp: current_time,
        expiry_duration: 3600,
    };

    let signature = sign_payload(&env, &signing_key, &payload);

    // Mint should succeed and return the amount
    let result = client.mint(&payload, &signature);
    assert_eq!(result, mint_amount);
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn test_mint_expired_signature() {
    let (env, client) = setup_test_env();
    let (signing_key, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

    let user = Address::generate(&env);
    let payload = MintPayload {
        user,
        amount: 500_i128,
        timestamp: 1000,
        expiry_duration: 3600,
    };

    let signature = sign_payload(&env, &signing_key, &payload);

    // Set time way past expiry
    set_ledger_timestamp(&env, 10000);

    // Should panic with SignatureExpired
    client.mint(&payload, &signature);
}

#[test]
#[should_panic]
fn test_mint_tampered_amount() {
    let (env, client) = setup_test_env();
    let (signing_key, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

    let current_time = 1000u64;
    set_ledger_timestamp(&env, current_time);

    let user = Address::generate(&env);

    // Admin signs for 100 tokens
    let payload = MintPayload {
        user: user.clone(),
        amount: 100_i128,
        timestamp: current_time,
        expiry_duration: 3600,
    };

    let signature = sign_payload(&env, &signing_key, &payload);

    // User tries to claim 1000 tokens instead
    let tampered_payload = MintPayload {
        user,
        amount: 1000_i128, // Tampered!
        timestamp: current_time,
        expiry_duration: 3600,
    };

    // Should panic because signature doesn't match
    client.mint(&tampered_payload, &signature);
}

#[test]
fn test_mint_at_expiry_boundary() {
    let (env, client) = setup_test_env();
    let (signing_key, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

    let sign_time = 1000u64;
    let expiry_duration = 3600u64;

    let user = Address::generate(&env);
    let payload = MintPayload {
        user,
        amount: 100_i128,
        timestamp: sign_time,
        expiry_duration,
    };

    let signature = sign_payload(&env, &signing_key, &payload);

    // Set time exactly at expiry boundary (should still work)
    set_ledger_timestamp(&env, sign_time + expiry_duration);

    // Should succeed - we're exactly at the expiry time, not past it
    let result = client.mint(&payload, &signature);
    assert_eq!(result, 100_i128);
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn test_mint_one_second_after_expiry() {
    let (env, client) = setup_test_env();
    let (signing_key, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

    let sign_time = 1000u64;
    let expiry_duration = 3600u64;

    let user = Address::generate(&env);
    let payload = MintPayload {
        user,
        amount: 100_i128,
        timestamp: sign_time,
        expiry_duration,
    };

    let signature = sign_payload(&env, &signing_key, &payload);

    // Set time one second after expiry
    set_ledger_timestamp(&env, sign_time + expiry_duration + 1);

    // Should fail - we're past the expiry time
    client.mint(&payload, &signature);
}

// =============================================================================
// Edge Case Tests
// =============================================================================

#[test]
fn test_mint_zero_amount() {
    let (env, client) = setup_test_env();
    let (signing_key, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

    let current_time = 1000u64;
    set_ledger_timestamp(&env, current_time);

    let user = Address::generate(&env);
    let payload = MintPayload {
        user,
        amount: 0_i128,
        timestamp: current_time,
        expiry_duration: 3600,
    };

    let signature = sign_payload(&env, &signing_key, &payload);

    // Zero amount should still work (signature is valid)
    let result = client.mint(&payload, &signature);
    assert_eq!(result, 0_i128);
}

#[test]
fn test_multiple_mints_same_user() {
    let (env, client) = setup_test_env();
    let (signing_key, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

    let current_time = 1000u64;
    set_ledger_timestamp(&env, current_time);

    let user = Address::generate(&env);

    // First mint
    let payload1 = MintPayload {
        user: user.clone(),
        amount: 100_i128,
        timestamp: current_time,
        expiry_duration: 3600,
    };
    let signature1 = sign_payload(&env, &signing_key, &payload1);
    let result1 = client.mint(&payload1, &signature1);
    assert_eq!(result1, 100_i128);

    // Second mint with different amount
    let payload2 = MintPayload {
        user: user.clone(),
        amount: 200_i128,
        timestamp: current_time + 1, // Different timestamp makes it a unique payload
        expiry_duration: 3600,
    };
    let signature2 = sign_payload(&env, &signing_key, &payload2);
    let result2 = client.mint(&payload2, &signature2);
    assert_eq!(result2, 200_i128);
}

// =============================================================================
// Savings Plan Tests
// =============================================================================

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
fn test_create_savings_plan() {
    let (env, client) = setup_test_env();
    let (_, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

    let user = Address::generate(&env);
    let plan_type = PlanType::Flexi;
    let initial_deposit = 1000_i128;

    let plan_id = client.create_savings_plan(&user, &plan_type, &initial_deposit);
    assert_eq!(plan_id, 1);

    let plan = client.get_savings_plan(&user, &plan_id).unwrap();
    assert_eq!(plan.plan_id, plan_id);
    assert_eq!(plan.plan_type, plan_type);
    assert_eq!(plan.balance, initial_deposit);
}

#[test]
fn test_get_user_savings_plans() {
    let (env, client) = setup_test_env();
    let (_, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

    let user = Address::generate(&env);

    // Create multiple plans
    let plan1_id = client.create_savings_plan(&user, &PlanType::Flexi, &1000_i128);
    let plan2_id = client.create_savings_plan(&user, &PlanType::Lock(2000000), &2000_i128);

    let plans = client.get_user_savings_plans(&user);
    assert_eq!(plans.len(), 2);

    // Verify plans are returned correctly
    let mut plan_ids = std::vec::Vec::new();
    for p in plans.iter() {
        plan_ids.push(p.plan_id);
    }
    assert!(plan_ids.contains(&plan1_id));
    assert!(plan_ids.contains(&plan2_id));
}

#[test]
fn test_get_user() {
    let (env, client) = setup_test_env();
    let (_, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);
    let user = Address::generate(&env);

    // OLD (Option): assert!(client.get_user(&user).is_none());

    // NEW (Result): Check if it returns an Error (UserNotFound)
    let result = client.try_get_user(&user);
    assert_eq!(result, Err(Ok(SavingsError::UserNotFound)));

    // Create a savings plan
    client.create_savings_plan(&user, &PlanType::Flexi, &1000_i128);

    // User should now exist (Ok)
    let user_data = client.get_user(&user);
    assert_eq!(user_data.total_balance, 1000_i128);
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

#[test]
fn test_flexi_deposit_success() {
    let (env, client) = setup_test_env();
    let user = Address::generate(&env);

    // 1. Initialize the user first
    env.mock_all_auths();
    client.initialize_user(&user);

    // 2. Deposit into Flexi
    let deposit_amount = 5000_i128;
    client.deposit_flexi(&user, &deposit_amount);

    // 3. Verify the user's total balance increased
    let user_data = client.get_user(&user);
    assert_eq!(user_data.total_balance, deposit_amount);
}

#[test]
fn test_flexi_withdraw_success() {
    let (env, client) = setup_test_env();
    let user = Address::generate(&env);
    env.mock_all_auths();

    // Setup: Initialize and deposit
    client.initialize_user(&user);
    client.deposit_flexi(&user, &5000);

    // 1. Withdraw a portion
    client.withdraw_flexi(&user, &2000);

    // 2. Verify remaining balance
    let user_data = client.get_user(&user);
    assert_eq!(user_data.total_balance, 3000);
}

#[test]
fn test_flexi_withdraw_insufficient_funds() {
    let (env, client) = setup_test_env();
    let user = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&user);
    client.deposit_flexi(&user, &1000);

    // Attempt to withdraw more than available
    let result = client.try_withdraw_flexi(&user, &1500);

    // Verify it returns the specific error from your errors.rs
    assert_eq!(result, Err(Ok(SavingsError::InsufficientBalance)));
}

#[test]
fn test_flexi_invalid_amount() {
    let (env, client) = setup_test_env();
    let user = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&user);

    // Attempt to deposit zero or negative
    let result = client.try_deposit_flexi(&user, &0);
    assert_eq!(result, Err(Ok(SavingsError::InvalidAmount)));
}
// =============================================================================
// View Function Tests
// =============================================================================

#[test]
fn test_view_lock_saves() {
    let (env, client) = setup_test_env();
    let (_, admin_public_key) = generate_keypair(&env);
    client.initialize(&admin_public_key);
    let user = Address::generate(&env);

    env.mock_all_auths();
    match client.initialize_user(&user) {
        _ => {}
    }

    // Create a Lock Save
    let lock_until = 2000000;
    // We can't call `create_savings_plan` with Lock directly because we need to pass strict types?
    // Actually the helper `create_savings_plan` takes `PlanType`.
    let _plan_id = client.create_savings_plan(&user, &PlanType::Lock(lock_until), &1000_i128);

    // Test get_user_ongoing_lock_saves
    let ongoing = client.get_user_ongoing_lock_saves(&user);
    assert_eq!(ongoing.len(), 1);
    assert_eq!(ongoing.get(0).unwrap().balance, 1000_i128);
    assert_eq!(ongoing.get(0).unwrap().locked_until, lock_until);

    // Test get_lock_save
    let lock_save = client.get_lock_save(&user, &ongoing.get(0).unwrap().plan_id);
    assert_eq!(lock_save.balance, 1000_i128);

    // Test get_user_matured_lock_saves (empty initially)
    let matured = client.get_user_matured_lock_saves(&user);
    assert_eq!(matured.len(), 0);

    // Advance time to maturity
    set_ledger_timestamp(&env, lock_until + 1);

    // Now it should be matured
    let matured_after = client.get_user_matured_lock_saves(&user);
    assert_eq!(matured_after.len(), 1);
}

#[test]
fn test_view_goal_saves() {
    let (env, client) = setup_test_env();
    let (_, admin_public_key) = generate_keypair(&env);
    client.initialize(&admin_public_key);
    let user = Address::generate(&env);
    env.mock_all_auths();
    match client.initialize_user(&user) {
        _ => {}
    }

    let goal_name = symbol_short!("car");
    let target = 50000_i128;
    let _plan_id = client.create_savings_plan(
        &user,
        &PlanType::Goal(goal_name.clone(), target, 1),
        &1000_i128,
    );

    // Test get_user_live_goal_saves
    let live = client.get_user_live_goal_saves(&user);
    assert_eq!(live.len(), 1);
    let save = live.get(0).unwrap();
    assert_eq!(save.target_amount, target);
    assert_eq!(save.goal_name, goal_name);
    assert_eq!(save.is_completed, false);

    // Test get_goal_save
    let goal_save = client.get_goal_save(&user, &save.plan_id);
    assert_eq!(goal_save.balance, 1000_i128);

    // Test completed (empty)
    let completed = client.get_user_completed_goal_saves(&user);
    assert_eq!(completed.len(), 0);
}

#[test]
fn test_view_group_saves() {
    let (env, client) = setup_test_env();
    let (_, admin_public_key) = generate_keypair(&env);
    client.initialize(&admin_public_key);
    let user = Address::generate(&env);
    env.mock_all_auths();
    match client.initialize_user(&user) {
        _ => {}
    }

    let group_id = 999;
    let target = 100000_i128;
    let _plan_id = client.create_savings_plan(
        &user,
        &PlanType::Group(group_id, true, 1, target),
        &1000_i128,
    );

    // Test get_user_live_group_saves
    let live = client.get_user_live_group_saves(&user);
    assert_eq!(live.len(), 1);
    let save = live.get(0).unwrap();
    assert_eq!(save.group_id, group_id);

    // Test get_group_save
    let group_save = client.get_group_save(&user, &save.plan_id);
    assert_eq!(group_save.balance, 1000_i128);
}

#[test]
fn test_is_group_member() {
    let (env, client) = setup_test_env();
    let (_, admin_public_key) = generate_keypair(&env);
    client.initialize(&admin_public_key);
    let user = Address::generate(&env);
    env.mock_all_auths();
    match client.initialize_user(&user) {
        _ => {}
    }

    let group_id = 123;

    // Initially not a member
    assert_eq!(client.is_group_member(&group_id, &user), false);

    // Join group (create plan)
    client.create_savings_plan(&user, &PlanType::Group(group_id, true, 1, 1000), &500);

    // Now should be member
    assert_eq!(client.is_group_member(&group_id, &user), true);

    // Check contribution
    assert_eq!(client.get_group_member_contribution(&group_id, &user), 500);
}

// #[test]
// fn test_get_flexi_balance_user_not_found() {
//     let env = Env::default();
//     let user = test_address(2);

//     // User not initialized
//     assert_eq!(
//         flexi::get_flexi_balance(&env, user.clone()),
//         Err(SavingsError::UserNotFound)
//     );

//     // has_flexi_balance returns false for missing user balance
//     assert_eq!(flexi::has_flexi_balance(&env, user.clone()), false);
// }

#[test]
fn test_get_flexi_balance() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);

    let user = Address::generate(&env);

    // 👇 REQUIRED: initialize user first
    client.initialize_user(&user);

    // then deposit
    client.deposit_flexi(&user, &1000);

    // view function
    let balance = client.get_flexi_balance(&user);

    assert_eq!(balance, 1000);
}

#[test]
fn test_get_flexi_balance_user_not_found() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(NesteraContract, ());

    let client = NesteraContractClient::new(&env, &contract_id);

    let user = Address::generate(&env);

    let result = client.try_get_flexi_balance(&user);
    assert!(result.is_err());
}

// =============================================================================
// Group Save Tests
// =============================================================================

#[test]
fn test_create_group_save_success() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let creator = Address::generate(&env);
    let title = String::from_slice(&env, "Emergency Fund");
    let description = String::from_slice(&env, "Group emergency savings");
    let category = String::from_slice(&env, "emergency");
    let target_amount = 10000i128;
    let contribution_type = 0u32; // Fixed
    let contribution_amount = 100i128;
    let is_public = true;
    let start_time = 1000u64;
    let end_time = 2000u64;

    let group_id = client.create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &target_amount,
        &contribution_type,
        &contribution_amount,
        &is_public,
        &start_time,
        &end_time,
    );

    assert_eq!(group_id, 1u64); // First group should have ID 1
}

#[test]
fn test_create_group_save_stored_correctly() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let creator = Address::generate(&env);
    let title = String::from_slice(&env, "School Fees");
    let description = String::from_slice(&env, "Save for school fees");
    let category = String::from_slice(&env, "education");
    let target_amount = 50000i128;
    let contribution_type = 1u32; // Flexible
    let contribution_amount = 500i128;
    let is_public = false;
    let start_time = 5000u64;
    let end_time = 10000u64;

    let group_id = client.create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &target_amount,
        &contribution_type,
        &contribution_amount,
        &is_public,
        &start_time,
        &end_time,
    );

    // Verify the group was stored
    let retrieved_group = client.get_group_save(&group_id);
    assert!(retrieved_group.is_some());

    let group = retrieved_group.unwrap();
    assert_eq!(group.id, group_id);
    assert_eq!(group.creator, creator);
    assert_eq!(group.title, title);
    assert_eq!(group.description, description);
    assert_eq!(group.category, category);
    assert_eq!(group.target_amount, target_amount);
    assert_eq!(group.current_amount, 0i128); // Should start at 0
    assert_eq!(group.contribution_type, contribution_type);
    assert_eq!(group.contribution_amount, contribution_amount);
    assert_eq!(group.is_public, is_public);
    assert_eq!(group.member_count, 1u32); // Creator is first member
    assert_eq!(group.start_time, start_time);
    assert_eq!(group.end_time, end_time);
    assert_eq!(group.is_completed, false);
}

#[test]
fn test_create_group_save_creator_added_to_list() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let creator = Address::generate(&env);
    let title = String::from_slice(&env, "Vacation Fund");
    let description = String::from_slice(&env, "Save for vacation");
    let category = String::from_slice(&env, "leisure");

    let group_id = client.create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &10000i128,
        &0u32,
        &100i128,
        &true,
        &1000u64,
        &2000u64,
    );

    // Verify creator is in the user's groups list
    let user_groups = client.get_user_groups(&creator);
    assert_eq!(user_groups.len(), 1);
    assert_eq!(user_groups.get(0).unwrap(), group_id);
}

#[test]
fn test_create_group_save_auto_increment_ids() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let creator1 = Address::generate(&env);
    let creator2 = Address::generate(&env);

    let title = String::from_slice(&env, "Test Group");
    let description = String::from_slice(&env, "Test");
    let category = String::from_slice(&env, "test");

    let group_id_1 = client.create_group_save(
        &creator1,
        &title,
        &description,
        &category,
        &10000i128,
        &0u32,
        &100i128,
        &true,
        &1000u64,
        &2000u64,
    );

    let group_id_2 = client.create_group_save(
        &creator2,
        &title,
        &description,
        &category,
        &20000i128,
        &1u32,
        &200i128,
        &false,
        &1000u64,
        &2000u64,
    );

    assert_eq!(group_id_1, 1u64);
    assert_eq!(group_id_2, 2u64);
}

#[test]
fn test_create_group_save_invalid_target_amount() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let creator = Address::generate(&env);
    let title = String::from_slice(&env, "Test");
    let description = String::from_slice(&env, "Test");
    let category = String::from_slice(&env, "test");

    // Test with zero target_amount
    let result = client.try_create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &0i128,
        &0u32,
        &100i128,
        &true,
        &1000u64,
        &2000u64,
    );
    assert!(result.is_err());

    // Test with negative target_amount
    let result = client.try_create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &-1000i128,
        &0u32,
        &100i128,
        &true,
        &1000u64,
        &2000u64,
    );
    assert!(result.is_err());
}

#[test]
fn test_create_group_save_invalid_contribution_amount() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let creator = Address::generate(&env);
    let title = String::from_slice(&env, "Test");
    let description = String::from_slice(&env, "Test");
    let category = String::from_slice(&env, "test");

    // Test with zero contribution_amount
    let result = client.try_create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &10000i128,
        &0u32,
        &0i128,
        &true,
        &1000u64,
        &2000u64,
    );
    assert!(result.is_err());

    // Test with negative contribution_amount
    let result = client.try_create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &10000i128,
        &0u32,
        &-100i128,
        &true,
        &1000u64,
        &2000u64,
    );
    assert!(result.is_err());
}

#[test]
fn test_create_group_save_invalid_timestamps() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let creator = Address::generate(&env);
    let title = String::from_slice(&env, "Test");
    let description = String::from_slice(&env, "Test");
    let category = String::from_slice(&env, "test");

    // Test with start_time >= end_time
    let result = client.try_create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &10000i128,
        &0u32,
        &100i128,
        &true,
        &2000u64,
        &2000u64,
    );
    assert!(result.is_err());

    // Test with start_time > end_time
    let result = client.try_create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &10000i128,
        &0u32,
        &100i128,
        &true,
        &3000u64,
        &2000u64,
    );
    assert!(result.is_err());
}

#[test]
fn test_create_group_save_invalid_contribution_type() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let creator = Address::generate(&env);
    let title = String::from_slice(&env, "Test");
    let description = String::from_slice(&env, "Test");
    let category = String::from_slice(&env, "test");

    // Test with invalid contribution_type (> 2)
    let result = client.try_create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &10000i128,
        &3u32,
        &100i128,
        &true,
        &1000u64,
        &2000u64,
    );
    assert!(result.is_err());
}

#[test]
fn test_create_group_save_empty_title() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let creator = Address::generate(&env);
    let title = String::from_slice(&env, "");
    let description = String::from_slice(&env, "Test description");
    let category = String::from_slice(&env, "test");

    let result = client.try_create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &10000i128,
        &0u32,
        &100i128,
        &true,
        &1000u64,
        &2000u64,
    );
    assert!(result.is_err());
}

#[test]
fn test_create_group_save_empty_description() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let creator = Address::generate(&env);
    let title = String::from_slice(&env, "Test Title");
    let description = String::from_slice(&env, "");
    let category = String::from_slice(&env, "test");

    let result = client.try_create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &10000i128,
        &0u32,
        &100i128,
        &true,
        &1000u64,
        &2000u64,
    );
    assert!(result.is_err());
}

#[test]
fn test_create_group_save_empty_category() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let creator = Address::generate(&env);
    let title = String::from_slice(&env, "Test Title");
    let description = String::from_slice(&env, "Test description");
    let category = String::from_slice(&env, "");

    let result = client.try_create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &10000i128,
        &0u32,
        &100i128,
        &true,
        &1000u64,
        &2000u64,
    );
    assert!(result.is_err());
}

#[test]
fn test_get_group_save_not_found() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let result = client.get_group_save(&999u64);
    assert!(result.is_none());
}

#[test]
fn test_group_exists() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let creator = Address::generate(&env);
    let title = String::from_slice(&env, "Test");
    let description = String::from_slice(&env, "Test");
    let category = String::from_slice(&env, "test");

    let group_id = client.create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &10000i128,
        &0u32,
        &100i128,
        &true,
        &1000u64,
        &2000u64,
    );

    assert!(client.group_exists(&group_id));
    assert!(!client.group_exists(&999u64));
}

#[test]
fn test_get_user_groups_multiple() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let creator = Address::generate(&env);
    let title = String::from_slice(&env, "Test");
    let description = String::from_slice(&env, "Test");
    let category = String::from_slice(&env, "test");

    // Create multiple groups
    let group_id_1 = client.create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &10000i128,
        &0u32,
        &100i128,
        &true,
        &1000u64,
        &2000u64,
    );

    let group_id_2 = client.create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &20000i128,
        &1u32,
        &200i128,
        &false,
        &1000u64,
        &2000u64,
    );

    let user_groups = client.get_user_groups(&creator);
    assert_eq!(user_groups.len(), 2);
    assert_eq!(user_groups.get(0).unwrap(), group_id_1);
    assert_eq!(user_groups.get(1).unwrap(), group_id_2);
}
// Lock Save Tests
// =============================================================================

#[test]
fn test_create_lock_save_success() {
    let (env, client) = setup_test_env();
    let (_, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

    let user = Address::generate(&env);
    env.mock_all_auths();

    // Initialize user first
    client.initialize_user(&user);

    let amount = 1000_i128;
    let duration = 86400u64; // 1 day

    let lock_id = client.create_lock_save(&user, &amount, &duration);
    assert_eq!(lock_id, 1);

    // Verify the lock save was created correctly
    let lock_save = client.get_lock_save(&lock_id);
    assert_eq!(lock_save.id, lock_id);
    assert_eq!(lock_save.owner, user);
    assert_eq!(lock_save.amount, amount);
    assert_eq!(lock_save.interest_rate, 500); // Default 5%
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
    let (_, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

    let user = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&user);

    // Should panic with InvalidAmount error
    client.create_lock_save(&user, &0, &86400u64);
}

#[test]
#[should_panic(expected = "Error(Contract, #50)")]
fn test_create_lock_save_invalid_duration() {
    let (env, client) = setup_test_env();
    let (_, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

    let user = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&user);

    // Should panic with InvalidTimestamp error
    client.create_lock_save(&user, &1000, &0);
}

#[test]
#[should_panic(expected = "Error(Contract, #10)")]
fn test_create_lock_save_user_not_found() {
    let (env, client) = setup_test_env();
    let (_, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

    let user = Address::generate(&env);
    env.mock_all_auths();

    // Don't initialize user - should panic with UserNotFound
    client.create_lock_save(&user, &1000, &86400u64);
}

#[test]
fn test_check_matured_lock_not_matured() {
    let (env, client) = setup_test_env();
    let (_, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

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
    let (_, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

    // Set initial timestamp
    set_ledger_timestamp(&env, 1000);

    let user = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&user);

    let lock_id = client.create_lock_save(&user, &1000, &100u64);

    // Advance time past maturity
    set_ledger_timestamp(&env, 1200); // 1000 + 100 + buffer

    assert!(client.check_matured_lock(&lock_id));
}

#[test]
fn test_check_matured_lock_nonexistent() {
    let (env, client) = setup_test_env();
    let (_, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

    // Non-existent lock should return false
    assert!(!client.check_matured_lock(&999));
}

#[test]
fn test_withdraw_lock_save_success() {
    let (env, client) = setup_test_env();
    let (_, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

    // Set initial timestamp
    set_ledger_timestamp(&env, 1000);

    let user = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&user);

    let lock_id = client.create_lock_save(&user, &1000, &100u64);

    // Advance time past maturity
    set_ledger_timestamp(&env, 1200);

    let amount = client.withdraw_lock_save(&user, &lock_id);
    assert!(amount >= 1000); // Should include some interest

    // Verify lock save is marked as withdrawn
    let lock_save = client.get_lock_save(&lock_id);
    assert!(lock_save.is_withdrawn);
}

#[test]
#[should_panic(expected = "Error(Contract, #51)")]
fn test_withdraw_lock_save_not_matured() {
    let (env, client) = setup_test_env();
    let (_, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

    let user = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&user);

    let lock_id = client.create_lock_save(&user, &1000, &86400u64);

    // Should panic with TooEarly error
    client.withdraw_lock_save(&user, &lock_id);
}

#[test]
#[should_panic(expected = "Error(Contract, #23)")]
fn test_withdraw_lock_save_already_withdrawn() {
    let (env, client) = setup_test_env();
    let (_, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

    // Set initial timestamp
    set_ledger_timestamp(&env, 1000);

    let user = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&user);

    let lock_id = client.create_lock_save(&user, &1000, &100u64);

    // Advance time past maturity
    set_ledger_timestamp(&env, 1200);

    // First withdrawal should succeed
    client.withdraw_lock_save(&user, &lock_id);

    // Second withdrawal should panic with PlanCompleted
    client.withdraw_lock_save(&user, &lock_id);
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn test_withdraw_lock_save_unauthorized() {
    let (env, client) = setup_test_env();
    let (_, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

    // Set initial timestamp
    set_ledger_timestamp(&env, 1000);

    let user1 = Address::generate(&env);
    let user2 = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&user1);
    client.initialize_user(&user2);

    let lock_id = client.create_lock_save(&user1, &1000, &100u64);

    // Advance time past maturity
    set_ledger_timestamp(&env, 1200);

    // User2 trying to withdraw user1's lock save should panic with Unauthorized
    client.withdraw_lock_save(&user2, &lock_id);
}

#[test]
#[should_panic(expected = "Error(Contract, #20)")]
fn test_withdraw_lock_save_plan_not_found() {
    let (env, client) = setup_test_env();
    let (_, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

    let user = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&user);

    // Should panic with PlanNotFound
    client.withdraw_lock_save(&user, &999);
}

#[test]
#[should_panic(expected = "Error(Contract, #20)")]
fn test_get_lock_save_plan_not_found() {
    let (env, client) = setup_test_env();
    let (_, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

    // Should panic with PlanNotFound
    client.get_lock_save(&999);
}

#[test]
fn test_multiple_lock_saves_unique_ids() {
    let (env, client) = setup_test_env();
    let (_, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

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

    let mut lock_ids = std::vec::Vec::new();
    for i in 0..user_locks.len() {
        lock_ids.push(user_locks.get(i).unwrap());
    }
    assert!(lock_ids.contains(&lock_id1));
    assert!(lock_ids.contains(&lock_id2));
}

#[test]
fn test_lock_save_stores_correct_times() {
    let (env, client) = setup_test_env();
    let (_, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

    let start_time = 1000u64;
    let duration = 86400u64;
    set_ledger_timestamp(&env, start_time);

    let user = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&user);

    let lock_id = client.create_lock_save(&user, &1000, &duration);

    let lock_save = client.get_lock_save(&lock_id);
    assert_eq!(lock_save.start_time, start_time);
    assert_eq!(lock_save.maturity_time, start_time + duration);
}

#[test]
fn test_get_user_lock_saves_empty() {
    let (env, client) = setup_test_env();
    let (_, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

    let user = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&user);

    // User with no lock saves should return empty vector
    let user_locks = client.get_user_lock_saves(&user);
    assert_eq!(user_locks.len(), 0);
}

#[test]
fn test_lock_save_balance_update() {
    let (env, client) = setup_test_env();
    let (_, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

    // Set initial timestamp
    set_ledger_timestamp(&env, 1000);

    let user = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&user);

    let initial_amount = 1000_i128;
    let lock_id = client.create_lock_save(&user, &initial_amount, &(365 * 24 * 3600)); // 1 year

    // Advance time by 6 months
    set_ledger_timestamp(&env, 1000 + (365 * 24 * 3600 / 2));

    // Verify lock is not matured yet
    assert!(!client.check_matured_lock(&lock_id));

    // Advance time to full maturity
    set_ledger_timestamp(&env, 1000 + (365 * 24 * 3600) + 1);

    // Now it should be matured
    assert!(client.check_matured_lock(&lock_id));

    // Withdraw and verify interest was calculated
    let final_amount = client.withdraw_lock_save(&user, &lock_id);
    assert!(final_amount > initial_amount); // Should have earned interest
}

#[test]
fn test_lock_save_wrong_plan_type() {
    let (env, client) = setup_test_env();
    let (_, admin_public_key) = generate_keypair(&env);

    client.initialize(&admin_public_key);

    let user = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&user);

    // Create a regular savings plan
    let savings_plan_id = client.create_savings_plan(&user, &PlanType::Flexi, &1000);

    // Create a lock save
    let lock_id = client.create_lock_save(&user, &1000, &86400u64);

    // These should be different types of plans stored separately
    // The savings plan ID and lock save ID can be the same since they're in different storage spaces

    // Verify lock save exists and has correct data
    let lock_save = client.get_lock_save(&lock_id);
    assert_eq!(lock_save.id, lock_id);
    assert_eq!(lock_save.amount, 1000);

    // Verify savings plan exists and has correct data
    let savings_plan = client.get_savings_plan(&user, &savings_plan_id).unwrap();
    assert_eq!(savings_plan.plan_id, savings_plan_id);
    assert_eq!(savings_plan.balance, 1000);

    // They are different types of plans even if they have the same ID
    // Lock saves are stored in DataKey::LockSave(id)
    // Savings plans are stored in DataKey::SavingsPlan(user, id)
}

#[test]
fn test_xdr_compatibility_lock_save() {
    let env = Env::default();
    let user = Address::generate(&env);

    let lock_save = crate::LockSave {
        id: 1,
        owner: user,
        amount: 1000,
        interest_rate: 500,
        start_time: 1000,
        maturity_time: 2000,
        is_withdrawn: false,
    };

    // Test XDR serialization/deserialization
    let xdr_bytes = lock_save.to_xdr(&env);
    assert!(!xdr_bytes.is_empty());

    // This verifies the struct can be serialized to XDR format
    // which is required for Soroban storage
}

// =============================================================================
// Group Save Join and Contribute Tests
// =============================================================================

#[test]
fn test_join_group_save_success() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let creator = Address::generate(&env);
    let joiner = Address::generate(&env);

    // Initialize both users
    client.initialize_user(&creator);
    client.initialize_user(&joiner);

    // Create a public group
    let title = String::from_slice(&env, "Test Group");
    let description = String::from_slice(&env, "Test");
    let category = String::from_slice(&env, "test");

    let group_id = client.create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &10000i128,
        &0u32,
        &100i128,
        &true, // public
        &1000u64,
        &2000u64,
    );

    // Joiner joins the group
    client.join_group_save(&joiner, &group_id);

    // Verify group member count increased
    let group = client.get_group_save(&group_id).unwrap();
    assert_eq!(group.member_count, 2u32);

    // Verify joiner is in the group members list
    let members = client.get_group_members(&group_id);
    assert_eq!(members.len(), 2);

    // Verify joiner's contribution is initialized to 0
    let contribution = client.get_member_contribution(&group_id, &joiner);
    assert_eq!(contribution, 0i128);

    // Verify joiner has the group in their list
    let joiner_groups = client.get_user_groups(&joiner);
    assert_eq!(joiner_groups.len(), 1);
    assert_eq!(joiner_groups.get(0).unwrap(), group_id);
}

#[test]
fn test_join_group_save_user_not_found() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let creator = Address::generate(&env);
    let joiner = Address::generate(&env);

    // Initialize only creator
    client.initialize_user(&creator);

    // Create a public group
    let title = String::from_slice(&env, "Test Group");
    let description = String::from_slice(&env, "Test");
    let category = String::from_slice(&env, "test");

    let group_id = client.create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &10000i128,
        &0u32,
        &100i128,
        &true,
        &1000u64,
        &2000u64,
    );

    // Joiner (not initialized) tries to join
    let result = client.try_join_group_save(&joiner, &group_id);
    assert_eq!(result, Err(Ok(SavingsError::UserNotFound)));
}

#[test]
fn test_join_group_save_group_not_found() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let joiner = Address::generate(&env);
    client.initialize_user(&joiner);

    // Try to join non-existent group
    let result = client.try_join_group_save(&joiner, &999u64);
    assert_eq!(result, Err(Ok(SavingsError::PlanNotFound)));
}

#[test]
fn test_join_group_save_private_group() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let creator = Address::generate(&env);
    let joiner = Address::generate(&env);

    client.initialize_user(&creator);
    client.initialize_user(&joiner);

    // Create a private group
    let title = String::from_slice(&env, "Private Group");
    let description = String::from_slice(&env, "Test");
    let category = String::from_slice(&env, "test");

    let group_id = client.create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &10000i128,
        &0u32,
        &100i128,
        &false, // private
        &1000u64,
        &2000u64,
    );

    // Joiner tries to join private group
    let result = client.try_join_group_save(&joiner, &group_id);
    assert_eq!(result, Err(Ok(SavingsError::InvalidGroupConfig)));
}

#[test]
fn test_join_group_save_already_member() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let creator = Address::generate(&env);

    client.initialize_user(&creator);

    // Create a public group
    let title = String::from_slice(&env, "Test Group");
    let description = String::from_slice(&env, "Test");
    let category = String::from_slice(&env, "test");

    let group_id = client.create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &10000i128,
        &0u32,
        &100i128,
        &true,
        &1000u64,
        &2000u64,
    );

    // Creator tries to join again
    let result = client.try_join_group_save(&creator, &group_id);
    assert_eq!(result, Err(Ok(SavingsError::InvalidGroupConfig)));
}

#[test]
fn test_contribute_to_group_save_success() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let creator = Address::generate(&env);
    client.initialize_user(&creator);

    // Create a public group
    let title = String::from_slice(&env, "Test Group");
    let description = String::from_slice(&env, "Test");
    let category = String::from_slice(&env, "test");

    let group_id = client.create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &10000i128,
        &0u32,
        &100i128,
        &true,
        &1000u64,
        &2000u64,
    );

    // Creator contributes
    client.contribute_to_group_save(&creator, &group_id, &500i128);

    // Verify group current_amount updated
    let group = client.get_group_save(&group_id).unwrap();
    assert_eq!(group.current_amount, 500i128);
    assert!(!group.is_completed);

    // Verify creator's contribution updated
    let contribution = client.get_member_contribution(&group_id, &creator);
    assert_eq!(contribution, 500i128);
}

#[test]
fn test_contribute_to_group_save_multiple_contributions() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let creator = Address::generate(&env);
    client.initialize_user(&creator);

    // Create a public group
    let title = String::from_slice(&env, "Test Group");
    let description = String::from_slice(&env, "Test");
    let category = String::from_slice(&env, "test");

    let group_id = client.create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &10000i128,
        &0u32,
        &100i128,
        &true,
        &1000u64,
        &2000u64,
    );

    // Multiple contributions
    client.contribute_to_group_save(&creator, &group_id, &300i128);
    client.contribute_to_group_save(&creator, &group_id, &200i128);
    client.contribute_to_group_save(&creator, &group_id, &500i128);

    // Verify total contribution
    let contribution = client.get_member_contribution(&group_id, &creator);
    assert_eq!(contribution, 1000i128);

    // Verify group current_amount
    let group = client.get_group_save(&group_id).unwrap();
    assert_eq!(group.current_amount, 1000i128);
}

#[test]
fn test_contribute_to_group_save_goal_reached() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let creator = Address::generate(&env);
    client.initialize_user(&creator);

    // Create a public group with low target
    let title = String::from_slice(&env, "Test Group");
    let description = String::from_slice(&env, "Test");
    let category = String::from_slice(&env, "test");

    let group_id = client.create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &1000i128, // low target
        &0u32,
        &100i128,
        &true,
        &1000u64,
        &2000u64,
    );

    // Contribute exactly the target amount
    client.contribute_to_group_save(&creator, &group_id, &1000i128);

    // Verify group is completed
    let group = client.get_group_save(&group_id).unwrap();
    assert_eq!(group.current_amount, 1000i128);
    assert!(group.is_completed);
}

#[test]
fn test_contribute_to_group_save_exceeds_goal() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let creator = Address::generate(&env);
    client.initialize_user(&creator);

    // Create a public group
    let title = String::from_slice(&env, "Test Group");
    let description = String::from_slice(&env, "Test");
    let category = String::from_slice(&env, "test");

    let group_id = client.create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &1000i128,
        &0u32,
        &100i128,
        &true,
        &1000u64,
        &2000u64,
    );

    // Contribute more than target
    client.contribute_to_group_save(&creator, &group_id, &1500i128);

    // Verify group is completed and has excess
    let group = client.get_group_save(&group_id).unwrap();
    assert_eq!(group.current_amount, 1500i128);
    assert!(group.is_completed);
}

#[test]
fn test_contribute_to_group_save_invalid_amount() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let creator = Address::generate(&env);
    client.initialize_user(&creator);

    // Create a public group
    let title = String::from_slice(&env, "Test Group");
    let description = String::from_slice(&env, "Test");
    let category = String::from_slice(&env, "test");

    let group_id = client.create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &10000i128,
        &0u32,
        &100i128,
        &true,
        &1000u64,
        &2000u64,
    );

    // Try to contribute zero
    let result = client.try_contribute_to_group_save(&creator, &group_id, &0i128);
    assert_eq!(result, Err(Ok(SavingsError::InvalidAmount)));

    // Try to contribute negative
    let result = client.try_contribute_to_group_save(&creator, &group_id, &-100i128);
    assert_eq!(result, Err(Ok(SavingsError::InvalidAmount)));
}

#[test]
fn test_contribute_to_group_save_not_member() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let creator = Address::generate(&env);
    let non_member = Address::generate(&env);

    client.initialize_user(&creator);
    client.initialize_user(&non_member);

    // Create a public group
    let title = String::from_slice(&env, "Test Group");
    let description = String::from_slice(&env, "Test");
    let category = String::from_slice(&env, "test");

    let group_id = client.create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &10000i128,
        &0u32,
        &100i128,
        &true,
        &1000u64,
        &2000u64,
    );

    // Non-member tries to contribute
    let result = client.try_contribute_to_group_save(&non_member, &group_id, &500i128);
    assert_eq!(result, Err(Ok(SavingsError::NotGroupMember)));
}

#[test]
fn test_contribute_to_group_save_group_not_found() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let user = Address::generate(&env);
    client.initialize_user(&user);

    // Try to contribute to non-existent group
    let result = client.try_contribute_to_group_save(&user, &999u64, &500i128);
    assert_eq!(result, Err(Ok(SavingsError::PlanNotFound)));
}

#[test]
fn test_multiple_members_contribute() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let creator = Address::generate(&env);
    let member1 = Address::generate(&env);
    let member2 = Address::generate(&env);

    client.initialize_user(&creator);
    client.initialize_user(&member1);
    client.initialize_user(&member2);

    // Create a public group
    let title = String::from_slice(&env, "Test Group");
    let description = String::from_slice(&env, "Test");
    let category = String::from_slice(&env, "test");

    let group_id = client.create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &10000i128,
        &0u32,
        &100i128,
        &true,
        &1000u64,
        &2000u64,
    );

    // Members join
    client.join_group_save(&member1, &group_id);
    client.join_group_save(&member2, &group_id);

    // All contribute different amounts
    client.contribute_to_group_save(&creator, &group_id, &1000i128);
    client.contribute_to_group_save(&member1, &group_id, &2000i128);
    client.contribute_to_group_save(&member2, &group_id, &3000i128);

    // Verify individual contributions
    assert_eq!(
        client.get_member_contribution(&group_id, &creator),
        1000i128
    );
    assert_eq!(
        client.get_member_contribution(&group_id, &member1),
        2000i128
    );
    assert_eq!(
        client.get_member_contribution(&group_id, &member2),
        3000i128
    );

    // Verify total group amount
    let group = client.get_group_save(&group_id).unwrap();
    assert_eq!(group.current_amount, 6000i128);
    assert_eq!(group.member_count, 3u32);

    // Verify all members are in the list
    let members = client.get_group_members(&group_id);
    assert_eq!(members.len(), 3);
}

#[test]
fn test_get_group_members() {
    let (env, client) = setup_test_env();
    env.mock_all_auths();

    let creator = Address::generate(&env);
    let member1 = Address::generate(&env);

    client.initialize_user(&creator);
    client.initialize_user(&member1);

    // Create a public group
    let title = String::from_slice(&env, "Test Group");
    let description = String::from_slice(&env, "Test");
    let category = String::from_slice(&env, "test");

    let group_id = client.create_group_save(
        &creator,
        &title,
        &description,
        &category,
        &10000i128,
        &0u32,
        &100i128,
        &true,
        &1000u64,
        &2000u64,
    );

    // Initially, only creator is a member
    let members = client.get_group_members(&group_id);
    assert_eq!(members.len(), 1);
    assert_eq!(members.get(0).unwrap(), creator);

    // Member joins
    client.join_group_save(&member1, &group_id);

    // Now there should be 2 members
    let members = client.get_group_members(&group_id);
    assert_eq!(members.len(), 2);
}
