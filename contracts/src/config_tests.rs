use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, InvokeError};

use crate::{NesteraContract, NesteraContractClient, SavingsError};

// ========== Test Helpers ==========

/// Sets up a test environment with the contract deployed and initialized
fn setup() -> (Env, NesteraContractClient<'static>, Address) {
    let env = Env::default();
    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let admin_pk = BytesN::from_array(&env, &[1u8; 32]);

    env.mock_all_auths();
    client.initialize(&admin, &admin_pk);

    (env, client, admin)
}

fn assert_savings_error(err: Result<SavingsError, InvokeError>, expected: SavingsError) {
    assert_eq!(err, Ok(expected));
}

// ========== initialize_config Tests ==========

#[test]
fn test_initialize_config_succeeds() {
    let (env, client, admin) = setup();
    let treasury = Address::generate(&env);

    env.mock_all_auths();
    let result = client.try_initialize_config(&admin, &treasury, &100, &100, &100);
    assert!(result.is_ok(), "initialize_config should succeed");

    // Verify stored values
    let config = client.get_config();
    assert_eq!(config.admin, admin);
    assert_eq!(config.treasury, treasury);
    assert_eq!(config.performance_fee_bps, 100);
    assert!(!config.paused);
}

#[test]
fn test_initialize_config_zero_fee() {
    let (env, client, admin) = setup();
    let treasury = Address::generate(&env);

    env.mock_all_auths();
    let result = client.try_initialize_config(&admin, &treasury, &0, &0, &0);
    assert!(result.is_ok(), "zero fee should be valid");

    let config = client.get_config();
    assert_eq!(config.performance_fee_bps, 0);
}

#[test]
fn test_initialize_config_max_fee() {
    let (env, client, admin) = setup();
    let treasury = Address::generate(&env);

    env.mock_all_auths();
    let result = client.try_initialize_config(&admin, &treasury, &10_000, &10_000, &10_000);
    assert!(result.is_ok(), "max fee (10000 bps = 100%) should be valid");

    let config = client.get_config();
    assert_eq!(config.performance_fee_bps, 10_000);
}

#[test]
fn test_reinitialize_config_fails() {
    let (env, client, admin) = setup();
    let treasury = Address::generate(&env);

    env.mock_all_auths();
    assert!(client
        .try_initialize_config(&admin, &treasury, &100, &100, &100)
        .is_ok());

    // Second initialization should fail
    let treasury2 = Address::generate(&env);
    assert_savings_error(
        client
            .try_initialize_config(&admin, &treasury2, &200, &200, &200)
            .unwrap_err(),
        SavingsError::ConfigAlreadyInitialized,
    );
}

#[test]
fn test_initialize_config_fee_too_high() {
    let (env, client, admin) = setup();
    let treasury = Address::generate(&env);

    env.mock_all_auths();
    assert_savings_error(
        client
            .try_initialize_config(&admin, &treasury, &10_001, &10_001, &10_001)
            .unwrap_err(),
        SavingsError::InvalidFeeBps,
    );
}

#[test]
fn test_non_admin_cannot_initialize_config() {
    let (env, client, _admin) = setup();
    let non_admin = Address::generate(&env);
    let treasury = Address::generate(&env);

    env.mock_all_auths();
    assert_savings_error(
        client
            .try_initialize_config(&non_admin, &treasury, &100, &100, &100)
            .unwrap_err(),
        SavingsError::Unauthorized,
    );
}

// ========== get_config Tests ==========

#[test]
fn test_get_config_before_config_init() {
    let (env, client, admin) = setup();

    env.mock_all_auths();
    // Config should still be retrievable with defaults even without initialize_config
    let config = client.get_config();
    assert_eq!(config.admin, admin);
    assert_eq!(config.performance_fee_bps, 0); // default
    assert!(!config.paused); // default
}

#[test]
fn test_get_config_reflects_updates() {
    let (env, client, admin) = setup();
    let treasury = Address::generate(&env);
    let new_treasury = Address::generate(&env);

    env.mock_all_auths();
    client.initialize_config(&admin, &treasury, &100, &100, &100);

    // Update treasury
    client.set_treasury(&admin, &new_treasury);

    // Update fee
    client.set_fees(&admin, &500, &500, &500);

    let config = client.get_config();
    assert_eq!(config.treasury, new_treasury);
    assert_eq!(config.performance_fee_bps, 500);
}

// ========== set_treasury Tests ==========

#[test]
fn test_set_treasury_succeeds() {
    let (env, client, admin) = setup();
    let treasury = Address::generate(&env);
    let new_treasury = Address::generate(&env);

    env.mock_all_auths();
    client.initialize_config(&admin, &treasury, &100, &100, &100);

    let result = client.try_set_treasury(&admin, &new_treasury);
    assert!(result.is_ok(), "admin should be able to update treasury");

    let config = client.get_config();
    assert_eq!(config.treasury, new_treasury);
}

#[test]
fn test_non_admin_cannot_set_treasury() {
    let (env, client, admin) = setup();
    let treasury = Address::generate(&env);
    let non_admin = Address::generate(&env);
    let new_treasury = Address::generate(&env);

    env.mock_all_auths();
    client.initialize_config(&admin, &treasury, &100, &100, &100);

    assert_savings_error(
        client
            .try_set_treasury(&non_admin, &new_treasury)
            .unwrap_err(),
        SavingsError::Unauthorized,
    );
}

// ========== set_protocol_fee Tests ==========

#[test]
fn test_set_protocol_fee_succeeds() {
    let (env, client, admin) = setup();
    let treasury = Address::generate(&env);

    env.mock_all_auths();
    client.initialize_config(&admin, &treasury, &100, &100, &100);

    let result = client.try_set_fees(&admin, &500, &500, &500);
    assert!(result.is_ok(), "admin should be able to update fee");

    let config = client.get_config();
    assert_eq!(config.performance_fee_bps, 500);
}

#[test]
fn test_set_protocol_fee_to_zero() {
    let (env, client, admin) = setup();
    let treasury = Address::generate(&env);

    env.mock_all_auths();
    client.initialize_config(&admin, &treasury, &100, &100, &100);

    let result = client.try_set_fees(&admin, &0, &0, &0);
    assert!(result.is_ok(), "setting fee to 0 should work");

    let config = client.get_config();
    assert_eq!(config.performance_fee_bps, 0);
}

#[test]
fn test_set_protocol_fee_to_max() {
    let (env, client, admin) = setup();
    let treasury = Address::generate(&env);

    env.mock_all_auths();
    client.initialize_config(&admin, &treasury, &100, &100, &100);

    let result = client.try_set_fees(&admin, &10_000, &10_000, &10_000);
    assert!(result.is_ok(), "setting fee to 10000 should work");
}

#[test]
fn test_set_protocol_fee_exceeds_max() {
    let (env, client, admin) = setup();
    let treasury = Address::generate(&env);

    env.mock_all_auths();
    client.initialize_config(&admin, &treasury, &100, &100, &100);

    assert_savings_error(
        client
            .try_set_fees(&admin, &10_001, &10_001, &10_001)
            .unwrap_err(),
        SavingsError::InvalidFeeBps,
    );
}

#[test]
fn test_non_admin_cannot_set_protocol_fee() {
    let (env, client, admin) = setup();
    let treasury = Address::generate(&env);
    let non_admin = Address::generate(&env);

    env.mock_all_auths();
    client.initialize_config(&admin, &treasury, &100, &100, &100);

    assert_savings_error(
        client
            .try_set_fees(&non_admin, &500, &500, &500)
            .unwrap_err(),
        SavingsError::Unauthorized,
    );
}

// ========== pause / unpause Tests ==========

#[test]
fn test_pause_contract_succeeds() {
    let (env, client, admin) = setup();

    env.mock_all_auths();
    let result = client.try_pause_contract(&admin);
    assert!(result.is_ok(), "admin should be able to pause");

    let config = client.get_config();
    assert!(config.paused);
}

#[test]
fn test_unpause_contract_succeeds() {
    let (env, client, admin) = setup();

    env.mock_all_auths();
    client.pause_contract(&admin);
    let result = client.try_unpause_contract(&admin);
    assert!(result.is_ok(), "admin should be able to unpause");

    let config = client.get_config();
    assert!(!config.paused);
}

#[test]
fn test_non_admin_cannot_pause() {
    let (env, client, _admin) = setup();
    let non_admin = Address::generate(&env);

    env.mock_all_auths();
    assert_savings_error(
        client.try_pause_contract(&non_admin).unwrap_err(),
        SavingsError::Unauthorized,
    );
}

#[test]
fn test_non_admin_cannot_unpause() {
    let (env, client, admin) = setup();
    let non_admin = Address::generate(&env);

    env.mock_all_auths();
    client.pause_contract(&admin);

    assert_savings_error(
        client.try_unpause_contract(&non_admin).unwrap_err(),
        SavingsError::Unauthorized,
    );
}

// ========== Pause Blocks State-Changing Operations ==========

#[test]
fn test_pause_blocks_deposit_flexi() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    env.mock_all_auths();
    client.initialize_user(&user);
    client.pause_contract(&admin);

    assert_savings_error(
        client.try_deposit_flexi(&user, &100).unwrap_err(),
        SavingsError::ContractPaused,
    );
}

#[test]
fn test_pause_blocks_withdraw_flexi() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    env.mock_all_auths();
    client.initialize_user(&user);
    client.deposit_flexi(&user, &100);
    client.pause_contract(&admin);

    assert_savings_error(
        client.try_withdraw_flexi(&user, &50).unwrap_err(),
        SavingsError::ContractPaused,
    );
}

#[test]
fn test_pause_blocks_create_autosave() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    env.mock_all_auths();
    client.initialize_user(&user);
    client.pause_contract(&admin);

    assert_savings_error(
        client
            .try_create_autosave(&user, &100, &3600, &1000)
            .unwrap_err(),
        SavingsError::ContractPaused,
    );
}

#[test]
fn test_pause_blocks_execute_autosave() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    env.mock_all_auths();
    client.initialize_user(&user);

    // Create autosave first while not paused
    let schedule_id = client.create_autosave(&user, &100, &3600, &0);

    // Now pause
    client.pause_contract(&admin);

    assert_savings_error(
        client.try_execute_autosave(&schedule_id).unwrap_err(),
        SavingsError::ContractPaused,
    );
}

#[test]
fn test_unpause_restores_operations() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    env.mock_all_auths();
    client.pause_contract(&admin);

    // Verify paused
    assert_savings_error(
        client.try_initialize_user(&user).unwrap_err(),
        SavingsError::ContractPaused,
    );

    // Unpause
    client.unpause_contract(&admin);

    // Should work now
    assert!(client.try_initialize_user(&user).is_ok());
}

// ========== Combined Admin Flow ==========

#[test]
fn test_full_config_lifecycle() {
    let (env, client, admin) = setup();
    let treasury1 = Address::generate(&env);
    let treasury2 = Address::generate(&env);

    env.mock_all_auths();

    // 1. Initialize config
    client.initialize_config(&admin, &treasury1, &250, &250, &250);

    let config = client.get_config();
    assert_eq!(config.treasury, treasury1);
    assert_eq!(config.performance_fee_bps, 250);
    assert!(!config.paused);

    // 2. Update treasury
    client.set_treasury(&admin, &treasury2);
    let config = client.get_config();
    assert_eq!(config.treasury, treasury2);

    // 3. Update fee
    client.set_fees(&admin, &500, &500, &500);
    let config = client.get_config();
    assert_eq!(config.deposit_fee_bps, 500);
    assert_eq!(config.withdrawal_fee_bps, 500);
    assert_eq!(config.performance_fee_bps, 500);

    // 4. Pause
    client.pause_contract(&admin);
    assert!(client.get_config().paused);

    // 5. Admin can still update config while paused
    client.set_fees(&admin, &300, &300, &300);
    assert_eq!(client.get_config().performance_fee_bps, 300);

    // 6. Unpause
    client.unpause_contract(&admin);
    assert!(!client.get_config().paused);
}
