use crate::errors::SavingsError;
use crate::strategy::routing::{self, StrategyPositionKey};
use crate::{NesteraContract, NesteraContractClient};
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env};

/// Helper: set up an env with an initialized contract and admin.
/// Returns (env, client, admin, contract_id).
fn setup() -> (Env, NesteraContractClient<'static>, Address, Address) {
    let env = Env::default();
    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let admin_pk = BytesN::from_array(&env, &[1u8; 32]);

    env.mock_all_auths();
    client.initialize(&admin, &admin_pk);

    (env, client, admin, contract_id)
}

// ========== Registry Tests ==========

#[test]
fn test_register_strategy() {
    let (env, client, admin, _) = setup();
    let strategy_addr = Address::generate(&env);

    let result = client.try_register_strategy(&admin, &strategy_addr, &1u32);
    assert!(result.is_ok());

    let info = client.get_strategy(&strategy_addr);
    assert_eq!(info.address, strategy_addr);
    assert!(info.enabled);
    assert_eq!(info.risk_level, 1);
}

#[test]
fn test_register_duplicate_strategy_fails() {
    let (env, client, admin, _) = setup();
    let strategy_addr = Address::generate(&env);

    client.register_strategy(&admin, &strategy_addr, &1u32);
    let result = client.try_register_strategy(&admin, &strategy_addr, &2u32);
    assert!(result.is_err());
}

#[test]
fn test_disable_strategy() {
    let (env, client, admin, _) = setup();
    let strategy_addr = Address::generate(&env);

    client.register_strategy(&admin, &strategy_addr, &1u32);
    client.disable_strategy(&admin, &strategy_addr);

    let info = client.get_strategy(&strategy_addr);
    assert!(!info.enabled);
}

#[test]
fn test_disable_nonexistent_strategy_fails() {
    let (env, client, admin, _) = setup();
    let strategy_addr = Address::generate(&env);

    let result = client.try_disable_strategy(&admin, &strategy_addr);
    assert!(result.is_err());
}

#[test]
fn test_get_strategy_not_found() {
    let (env, client, _admin, _) = setup();
    let strategy_addr = Address::generate(&env);

    let result = client.try_get_strategy(&strategy_addr);
    assert!(result.is_err());
}

#[test]
fn test_get_all_strategies() {
    let (env, client, admin, _) = setup();
    let s1 = Address::generate(&env);
    let s2 = Address::generate(&env);

    client.register_strategy(&admin, &s1, &0u32);
    client.register_strategy(&admin, &s2, &5u32);

    let all = client.get_all_strategies();
    assert_eq!(all.len(), 2);
}

#[test]
fn test_register_strategy_unauthorized() {
    let (env, client, _admin, _) = setup();
    let non_admin = Address::generate(&env);
    let strategy_addr = Address::generate(&env);

    let result = client.try_register_strategy(&non_admin, &strategy_addr, &1u32);
    assert!(result.is_err());
}

// ========== Routing Unit Tests ==========

#[test]
fn test_route_to_strategy_invalid_amount() {
    let (env, _client, _admin, contract_id) = setup();
    let strategy_addr = Address::generate(&env);

    env.as_contract(&contract_id, || {
        let position_key = StrategyPositionKey::Lock(1);
        let result = routing::route_to_strategy(&env, strategy_addr.clone(), position_key, 0);
        assert_eq!(result, Err(SavingsError::InvalidAmount));

        let position_key2 = StrategyPositionKey::Lock(2);
        let result2 =
            routing::route_to_strategy(&env, Address::generate(&env), position_key2, -100);
        assert_eq!(result2, Err(SavingsError::InvalidAmount));
    });
}

#[test]
fn test_route_to_unregistered_strategy_fails() {
    let (env, _client, _admin, contract_id) = setup();
    let strategy_addr = Address::generate(&env);

    env.as_contract(&contract_id, || {
        let position_key = StrategyPositionKey::Lock(1);
        let result = routing::route_to_strategy(&env, strategy_addr.clone(), position_key, 1000);
        assert_eq!(result, Err(SavingsError::StrategyNotFound));
    });
}

#[test]
fn test_route_to_disabled_strategy_fails() {
    let (env, client, admin, contract_id) = setup();
    let strategy_addr = Address::generate(&env);

    client.register_strategy(&admin, &strategy_addr, &1u32);
    client.disable_strategy(&admin, &strategy_addr);

    env.as_contract(&contract_id, || {
        let position_key = StrategyPositionKey::Lock(1);
        let result = routing::route_to_strategy(&env, strategy_addr.clone(), position_key, 1000);
        assert_eq!(result, Err(SavingsError::StrategyDisabled));
    });
}

#[test]
fn test_get_position_none_when_empty() {
    let (env, _client, _admin, contract_id) = setup();

    env.as_contract(&contract_id, || {
        let pos = routing::get_position(&env, StrategyPositionKey::Lock(999));
        assert!(pos.is_none());
    });
}
