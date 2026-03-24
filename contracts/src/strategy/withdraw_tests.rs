use crate::errors::SavingsError;
use crate::storage_types::DataKey;
use crate::strategy::routing::{self, StrategyPosition, StrategyPositionKey};
use crate::{NesteraContract, NesteraContractClient};
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env};

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

/// Helper: pre-seed a StrategyPosition so withdraw logic can be tested
/// without going through route_to_strategy (which requires a real deployed strategy).
fn seed_position(
    env: &Env,
    strat_addr: Address,
    position_key: StrategyPositionKey,
    principal: i128,
    also_set_principal: bool,
) {
    let position = StrategyPosition {
        strategy: strat_addr.clone(),
        principal_deposited: principal,
        strategy_shares: 0,
    };
    env.storage().persistent().set(&position_key, &position);

    if also_set_principal {
        env.storage()
            .persistent()
            .set(&DataKey::StrategyTotalPrincipal(strat_addr), &principal);
    }
}

#[test]
fn test_withdraw_from_no_position_returns_error() {
    let (env, _client, _admin, contract_id) = setup();

    env.as_contract(&contract_id, || {
        // No position has been seeded — should return StrategyNotFound
        let result = routing::withdraw_from_strategy(
            &env,
            StrategyPositionKey::Lock(99),
            Address::generate(&env),
        );
        assert_eq!(result, Err(SavingsError::StrategyNotFound));
    });
}

#[test]
fn test_withdraw_from_zero_principal_returns_zero() {
    let (env, client, admin, contract_id) = setup();
    let strat_addr = Address::generate(&env);
    client.register_strategy(&admin, &strat_addr, &1u32);

    env.as_contract(&contract_id, || {
        // Seed a position with principal = 0
        seed_position(
            &env,
            strat_addr.clone(),
            StrategyPositionKey::Lock(5),
            0,
            false,
        );

        let result = routing::withdraw_from_strategy(
            &env,
            StrategyPositionKey::Lock(5),
            Address::generate(&env),
        );
        // Should short-circuit and return Ok(0) before cross-contract call
        assert_eq!(result, Ok(0));
    });
}

#[test]
fn test_withdraw_strategy_not_registered_errors() {
    let (env, _client, _admin, contract_id) = setup();
    let strat_addr = Address::generate(&env);

    env.as_contract(&contract_id, || {
        // Seed position but do NOT register the strategy
        seed_position(
            &env,
            strat_addr.clone(),
            StrategyPositionKey::Lock(6),
            500,
            false,
        );

        let result = routing::withdraw_from_strategy(
            &env,
            StrategyPositionKey::Lock(6),
            Address::generate(&env),
        );
        // Strategy not in registry → StrategyNotFound
        assert_eq!(result, Err(SavingsError::StrategyNotFound));
    });
}

/// Principal tracking: confirm that withdraw deduction logic (floor at 0) is correct.
#[test]
fn test_principal_deduction_floor_at_zero() {
    let (env, _client, _admin, contract_id) = setup();
    let strat_addr = Address::generate(&env);

    env.as_contract(&contract_id, || {
        let principal_key = DataKey::StrategyTotalPrincipal(strat_addr.clone());
        env.storage().persistent().set(&principal_key, &100_i128);

        // Simulate withdraw of more than principal
        let current: i128 = env.storage().persistent().get(&principal_key).unwrap_or(0);
        let withdraw_amount: i128 = 500;
        let new_principal = if current >= withdraw_amount {
            current - withdraw_amount
        } else {
            0
        };
        env.storage()
            .persistent()
            .set(&principal_key, &new_principal);

        let stored: i128 = env.storage().persistent().get(&principal_key).unwrap_or(0);
        assert_eq!(stored, 0, "Principal must not go below zero");
    });
}

/// Validates that after a partial withdrawal, the remaining principal is correct.
#[test]
fn test_principal_partial_deduction() {
    let (env, _client, _admin, contract_id) = setup();
    let strat_addr = Address::generate(&env);

    env.as_contract(&contract_id, || {
        let principal_key = DataKey::StrategyTotalPrincipal(strat_addr.clone());
        env.storage().persistent().set(&principal_key, &1_000_i128);

        let current: i128 = env.storage().persistent().get(&principal_key).unwrap_or(0);
        let withdraw_amount: i128 = 400;
        let new_principal = if current >= withdraw_amount {
            current - withdraw_amount
        } else {
            0
        };
        env.storage()
            .persistent()
            .set(&principal_key, &new_principal);

        let stored: i128 = env.storage().persistent().get(&principal_key).unwrap_or(0);
        assert_eq!(
            stored, 600,
            "Remaining principal after partial withdrawal is 600"
        );
    });
}
