#![cfg(test)]
extern crate std;

use crate::{
    MintPayload, NesteraContract, NesteraContractClient, PlanType, SavingsError, SavingsPlan, User,
};
use ed25519_dalek::{Signer, SigningKey};
use soroban_sdk::testutils::{Address as _, Ledger, LedgerInfo};
use soroban_sdk::{symbol_short, xdr::ToXdr, Address, Bytes, BytesN, Env};

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
// Group Save Tests
// =============================================================================

#[test]
fn test_create_group_save_success() {
    let (env, client) = setup_test_env();
    let creator = Address::generate(&env);
    env.mock_all_auths();

    // Initialize creator
    client.initialize_user(&creator);

    // Create a public group
    let group_id = client.create_group_save(
        &creator,
        &true,      // is_public
        &10000_i128, // target_amount
        &5u32,      // max_members
        &1u32,      // contribution_type (weekly)
    );

    assert_eq!(group_id, 1);

    // Verify group was created
    let group = client.get_group(&group_id);
    assert_eq!(group.group_id, group_id);
    assert_eq!(group.is_public, true);
    assert_eq!(group.target_amount, 10000_i128);
    assert_eq!(group.current_amount, 0);
    assert_eq!(group.member_count, 1); // Creator is first member
    assert_eq!(group.max_members, 5);
    assert_eq!(group.is_completed, false);
}

#[test]
fn test_create_group_invalid_amount() {
    let (env, client) = setup_test_env();
    let creator = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&creator);

    // Try to create group with invalid target amount
    let result = client.try_create_group_save(&creator, &true, &0, &5u32, &1u32);
    assert_eq!(result, Err(Ok(SavingsError::InvalidAmount)));

    let result2 = client.try_create_group_save(&creator, &true, &-100, &5u32, &1u32);
    assert_eq!(result2, Err(Ok(SavingsError::InvalidAmount)));
}

#[test]
fn test_create_group_invalid_config() {
    let (env, client) = setup_test_env();
    let creator = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&creator);

    // Try to create group with 0 max_members
    let result = client.try_create_group_save(&creator, &true, &10000, &0u32, &1u32);
    assert_eq!(result, Err(Ok(SavingsError::InvalidGroupConfig)));
}

#[test]
fn test_join_group_save_success() {
    let (env, client) = setup_test_env();
    let creator = Address::generate(&env);
    let user = Address::generate(&env);
    env.mock_all_auths();

    // Initialize users
    client.initialize_user(&creator);
    client.initialize_user(&user);

    // Create a public group
    let group_id = client.create_group_save(&creator, &true, &10000_i128, &5u32, &1u32);

    // User joins the group
    client.join_group_save(&user, &group_id);

    // Verify user is a member
    assert!(client.is_group_member(&user, &group_id));

    // Verify member count increased
    let group = client.get_group(&group_id);
    assert_eq!(group.member_count, 2);

    // Verify user's contribution is 0
    assert_eq!(client.get_member_contribution(&group_id, &user), 0);
}

#[test]
fn test_join_group_user_not_found() {
    let (env, client) = setup_test_env();
    let creator = Address::generate(&env);
    let non_existent_user = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&creator);
    let group_id = client.create_group_save(&creator, &true, &10000_i128, &5u32, &1u32);

    // Try to join without being initialized
    let result = client.try_join_group_save(&non_existent_user, &group_id);
    assert_eq!(result, Err(Ok(SavingsError::UserNotFound)));
}

#[test]
fn test_join_group_plan_not_found() {
    let (env, client) = setup_test_env();
    let user = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&user);

    // Try to join non-existent group
    let result = client.try_join_group_save(&user, &999u64);
    assert_eq!(result, Err(Ok(SavingsError::PlanNotFound)));
}

#[test]
fn test_join_group_already_member() {
    let (env, client) = setup_test_env();
    let creator = Address::generate(&env);
    let user = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&creator);
    client.initialize_user(&user);

    let group_id = client.create_group_save(&creator, &true, &10000_i128, &5u32, &1u32);
    client.join_group_save(&user, &group_id);

    // Try to join again
    let result = client.try_join_group_save(&user, &group_id);
    assert_eq!(result, Err(Ok(SavingsError::UserAlreadyExists)));
}

#[test]
fn test_join_group_full() {
    let (env, client) = setup_test_env();
    let creator = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&creator);

    // Create a group with max 2 members (creator counts as 1)
    let group_id = client.create_group_save(&creator, &true, &10000_i128, &2u32, &1u32);

    // Add one more member
    let user1 = Address::generate(&env);
    client.initialize_user(&user1);
    client.join_group_save(&user1, &group_id);

    // Try to add another member (should fail - group full)
    let user2 = Address::generate(&env);
    client.initialize_user(&user2);
    let result = client.try_join_group_save(&user2, &group_id);
    assert_eq!(result, Err(Ok(SavingsError::GroupFull)));
}

#[test]
fn test_join_private_group_not_invited() {
    let (env, client) = setup_test_env();
    let creator = Address::generate(&env);
    let user = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&creator);
    client.initialize_user(&user);

    // Create a private group
    let group_id = client.create_group_save(&creator, &false, &10000_i128, &5u32, &1u32);

    // User tries to join private group (should fail)
    let result = client.try_join_group_save(&user, &group_id);
    assert_eq!(result, Err(Ok(SavingsError::NotGroupMember)));
}

#[test]
fn test_contribute_to_group_save_success() {
    let (env, client) = setup_test_env();
    let creator = Address::generate(&env);
    let user = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&creator);
    client.initialize_user(&user);

    let group_id = client.create_group_save(&creator, &true, &10000_i128, &5u32, &1u32);
    client.join_group_save(&user, &group_id);

    // User contributes to the group
    client.contribute_to_group_save(&user, &group_id, &2000_i128);

    // Verify contribution was recorded
    assert_eq!(client.get_member_contribution(&group_id, &user), 2000_i128);

    // Verify group current_amount increased
    let group = client.get_group(&group_id);
    assert_eq!(group.current_amount, 2000_i128);
    assert_eq!(group.is_completed, false); // Not yet reached target
}

#[test]
fn test_contribute_multiple_times() {
    let (env, client) = setup_test_env();
    let creator = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&creator);
    let group_id = client.create_group_save(&creator, &true, &10000_i128, &5u32, &1u32);

    // Creator contributes multiple times
    client.contribute_to_group_save(&creator, &group_id, &1000_i128);
    client.contribute_to_group_save(&creator, &group_id, &1500_i128);
    client.contribute_to_group_save(&creator, &group_id, &2500_i128);

    // Verify total contribution
    assert_eq!(
        client.get_member_contribution(&group_id, &creator),
        5000_i128
    );

    let group = client.get_group(&group_id);
    assert_eq!(group.current_amount, 5000_i128);
}

#[test]
fn test_contribute_reaches_target() {
    let (env, client) = setup_test_env();
    let creator = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&creator);
    let group_id = client.create_group_save(&creator, &true, &10000_i128, &5u32, &1u32);

    // Contribute exactly the target amount
    client.contribute_to_group_save(&creator, &group_id, &10000_i128);

    // Verify group is completed
    let group = client.get_group(&group_id);
    assert_eq!(group.current_amount, 10000_i128);
    assert_eq!(group.is_completed, true);
}

#[test]
fn test_contribute_exceeds_target() {
    let (env, client) = setup_test_env();
    let creator = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&creator);
    let group_id = client.create_group_save(&creator, &true, &10000_i128, &5u32, &1u32);

    // Contribute more than target
    client.contribute_to_group_save(&creator, &group_id, &15000_i128);

    // Verify group is completed and amount is recorded
    let group = client.get_group(&group_id);
    assert_eq!(group.current_amount, 15000_i128);
    assert_eq!(group.is_completed, true);
}

#[test]
fn test_contribute_invalid_amount() {
    let (env, client) = setup_test_env();
    let creator = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&creator);
    let group_id = client.create_group_save(&creator, &true, &10000_i128, &5u32, &1u32);

    // Try to contribute zero
    let result = client.try_contribute_to_group_save(&creator, &group_id, &0);
    assert_eq!(result, Err(Ok(SavingsError::InvalidAmount)));

    // Try to contribute negative
    let result2 = client.try_contribute_to_group_save(&creator, &group_id, &-100);
    assert_eq!(result2, Err(Ok(SavingsError::InvalidAmount)));
}

#[test]
fn test_contribute_not_a_member() {
    let (env, client) = setup_test_env();
    let creator = Address::generate(&env);
    let non_member = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&creator);
    client.initialize_user(&non_member);

    let group_id = client.create_group_save(&creator, &true, &10000_i128, &5u32, &1u32);

    // Non-member tries to contribute
    let result = client.try_contribute_to_group_save(&non_member, &group_id, &1000);
    assert_eq!(result, Err(Ok(SavingsError::NotGroupMember)));
}

#[test]
fn test_contribute_user_not_found() {
    let (env, client) = setup_test_env();
    let creator = Address::generate(&env);
    let non_existent = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&creator);
    let group_id = client.create_group_save(&creator, &true, &10000_i128, &5u32, &1u32);

    // Non-existent user tries to contribute
    let result = client.try_contribute_to_group_save(&non_existent, &group_id, &1000);
    assert_eq!(result, Err(Ok(SavingsError::UserNotFound)));
}

#[test]
fn test_multiple_members_contribute() {
    let (env, client) = setup_test_env();
    let creator = Address::generate(&env);
    let user1 = Address::generate(&env);
    let user2 = Address::generate(&env);
    env.mock_all_auths();

    // Initialize all users
    client.initialize_user(&creator);
    client.initialize_user(&user1);
    client.initialize_user(&user2);

    // Create group and add members
    let group_id = client.create_group_save(&creator, &true, &10000_i128, &5u32, &1u32);
    client.join_group_save(&user1, &group_id);
    client.join_group_save(&user2, &group_id);

    // Each member contributes
    client.contribute_to_group_save(&creator, &group_id, &3000_i128);
    client.contribute_to_group_save(&user1, &group_id, &2500_i128);
    client.contribute_to_group_save(&user2, &group_id, &4500_i128);

    // Verify individual contributions
    assert_eq!(client.get_member_contribution(&group_id, &creator), 3000_i128);
    assert_eq!(client.get_member_contribution(&group_id, &user1), 2500_i128);
    assert_eq!(client.get_member_contribution(&group_id, &user2), 4500_i128);

    // Verify total group amount and completion
    let group = client.get_group(&group_id);
    assert_eq!(group.current_amount, 10000_i128);
    assert_eq!(group.is_completed, true);
    assert_eq!(group.member_count, 3);
}

#[test]
fn test_get_group_not_found() {
    let (_, client) = setup_test_env();

    let result = client.try_get_group(&999u64);
    assert_eq!(result, Err(Ok(SavingsError::PlanNotFound)));
}

#[test]
fn test_is_group_member_false() {
    let (env, client) = setup_test_env();
    let creator = Address::generate(&env);
    let non_member = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&creator);
    let group_id = client.create_group_save(&creator, &true, &10000_i128, &5u32, &1u32);

    // Non-member check
    assert!(!client.is_group_member(&non_member, &group_id));
}

#[test]
fn test_creator_is_first_member() {
    let (env, client) = setup_test_env();
    let creator = Address::generate(&env);
    env.mock_all_auths();

    client.initialize_user(&creator);
    let group_id = client.create_group_save(&creator, &true, &10000_i128, &5u32, &1u32);

    // Creator should be a member
    assert!(client.is_group_member(&creator, &group_id));

    // Creator can contribute
    client.contribute_to_group_save(&creator, &group_id, &5000_i128);
    assert_eq!(client.get_member_contribution(&group_id, &creator), 5000_i128);
}
