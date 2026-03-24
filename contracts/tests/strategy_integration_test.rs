#![cfg(test)]

use soroban_sdk::{
    contract, contractimpl, testutils::Address as _, testutils::Ledger, Address, BytesN, Env,
    Symbol,
};

use Nestera::strategy::interface::YieldStrategy;
use Nestera::PlanType;
use Nestera::{NesteraContract, NesteraContractClient};

// --- Mock Yield Strategy ---

#[contract]
pub struct MockYieldStrategy;

#[contractimpl]
impl MockYieldStrategy {
    pub fn simulate_yield(env: Env, amount: i128) {
        let sym = Symbol::new(&env, "yield");
        let current: i128 = env.storage().instance().get(&sym).unwrap_or(0);
        env.storage().instance().set(&sym, &(current + amount));
    }
}

#[contractimpl]
impl YieldStrategy for MockYieldStrategy {
    fn strategy_deposit(env: Env, _from: Address, amount: i128) -> i128 {
        let sym = Symbol::new(&env, "principal");
        let current: i128 = env.storage().instance().get(&sym).unwrap_or(0);
        env.storage().instance().set(&sym, &(current + amount));
        amount // shares = amount
    }

    fn strategy_withdraw(env: Env, _to: Address, amount: i128) -> i128 {
        let sym = Symbol::new(&env, "principal");
        let current: i128 = env.storage().instance().get(&sym).unwrap_or(0);
        env.storage().instance().set(&sym, &(current - amount));
        amount
    }

    fn strategy_harvest(env: Env, _to: Address) -> i128 {
        let sym = Symbol::new(&env, "yield");
        let current: i128 = env.storage().instance().get(&sym).unwrap_or(0);
        env.storage().instance().set(&sym, &0i128); // reset yield
        current
    }

    fn strategy_balance(env: Env, _addr: Address) -> i128 {
        let p_sym = Symbol::new(&env, "principal");
        let y_sym = Symbol::new(&env, "yield");
        let p: i128 = env.storage().instance().get(&p_sym).unwrap_or(0);
        let y: i128 = env.storage().instance().get(&y_sym).unwrap_or(0);
        p + y
    }
}

// --- Setup ---

fn setup_env() -> (
    Env,
    NesteraContractClient<'static>,
    Address,
    Address,
    Address, // treasury
    Address, // strategy
) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let admin_pk = BytesN::from_array(&env, &[1u8; 32]);
    client.initialize(&admin, &admin_pk);
    client.initialize_config(&admin, &treasury, &1_000u32, &1_000u32, &1_000u32); // 10% fee

    let user1 = Address::generate(&env);
    let strategy_id = env.register(MockYieldStrategy, ());

    (env, client, admin, user1, treasury, strategy_id)
}

// --- Tests ---

#[test]
fn test_strategy_full_lifecycle() {
    let (env, client, admin, user1, treasury, strategy_id) = setup_env();

    // 1. Register strategy
    client.register_strategy(&admin, &strategy_id, &1u32);
    let strat_info = client.get_strategy(&strategy_id);
    assert!(strat_info.enabled);
    assert_eq!(strat_info.risk_level, 1);

    // 2. Deposit funds into protocol and create lock plan
    client.initialize_user(&user1);
    client.deposit_flexi(&user1, &50_000); // 50,000 to flexi

    let lock_amount: i128 = 10_000;
    let lock_duration: u64 = 30 * 86400; // 30 days
    let lock_id = client.create_lock_save(&user1, &lock_amount, &lock_duration);

    // 3. Route lock funds to strategy
    let shares = client.route_lock_to_strategy(&user1, &lock_id, &strategy_id, &lock_amount);
    assert_eq!(shares, lock_amount);

    let principal = env.as_contract(&client.address, || {
        let key = Nestera::DataKey::StrategyTotalPrincipal(strategy_id.clone());
        env.storage().persistent().get::<_, i128>(&key).unwrap_or(0)
    });
    assert_eq!(principal, lock_amount);

    let position = client.get_lock_strategy_position(&lock_id).unwrap();
    assert_eq!(position.strategy, strategy_id);
    assert_eq!(position.principal_deposited, lock_amount);

    // 4. Simulate yield growth using the mock strategy client
    let mock_client = MockYieldStrategyClient::new(&env, &strategy_id);
    let yield_amount: i128 = 1_000;
    mock_client.simulate_yield(&yield_amount);

    // 5. Harvest yield
    let harvested = client.harvest_strategy(&admin, &strategy_id);
    assert_eq!(harvested, yield_amount);

    // Verify fee allocations: 10% of 1,000 = 100 to treasury, 900 to user yield tracking
    let current_yield = env.as_contract(&client.address, || {
        let key = Nestera::DataKey::StrategyYield(strategy_id.clone());
        env.storage().persistent().get::<_, i128>(&key).unwrap_or(0)
    });
    assert_eq!(current_yield, 900);

    // Actually checking treasury balance via Nestera contract config functions:
    // (Assuming Nestera handles treasury balance mapping natively if we're not using tokens)
    // Wait, get_protocol_fee_balance exists on NesteraContract
    let treasury_balances = client.get_protocol_fee_balance(&treasury);
    assert_eq!(treasury_balances, 100);

    // 6. Withdraw user funds (strategy position)
    let withdrawn_from_strat = client.withdraw_lock_strategy(&user1, &lock_id, &user1);
    assert_eq!(withdrawn_from_strat, lock_amount);

    let empty_position = client.get_lock_strategy_position(&lock_id).unwrap();
    assert_eq!(empty_position.principal_deposited, 0);
    let new_principal = env.as_contract(&client.address, || {
        let key = Nestera::DataKey::StrategyTotalPrincipal(strategy_id.clone());
        env.storage().persistent().get::<_, i128>(&key).unwrap_or(0)
    });
    assert_eq!(new_principal, 0);

    // 7. Advance time & withdraw lock completely
    env.ledger().with_mut(|li| {
        li.timestamp += lock_duration + 1;
    });

    let final_returned = client.withdraw_lock_save(&user1, &lock_id);
    // Lock save yield is calculated off lock rate config, not directly 1:1 with strategy yield,
    // but the funds are there. We just ensure it works and doesn't panic.
    assert!(final_returned >= lock_amount);
}

#[test]
fn test_governance_disable_strategy() {
    let (_env, client, admin, user1, _treasury, strategy_id) = setup_env();

    // 1. Register Strategy
    client.register_strategy(&admin, &strategy_id, &1u32);

    // 2. User sets up lock
    client.initialize_user(&user1);
    client.deposit_flexi(&user1, &10_000);
    let lock_id = client.create_lock_save(&user1, &10_000, &30);

    // 3. Disable the strategy
    client.disable_strategy(&admin, &strategy_id);

    let strat_info = client.get_strategy(&strategy_id);
    assert!(!strat_info.enabled);

    // 4. Try to route funds, should fail with StrategyDisabled
    let res = client.try_route_lock_to_strategy(&user1, &lock_id, &strategy_id, &10_000);
    assert!(res.is_err());
}

#[test]
fn test_emergency_withdraw_scenario() {
    let (_env, client, admin, user1, _treasury, strategy_id) = setup_env();

    // 1. Register & Route
    client.register_strategy(&admin, &strategy_id, &1u32);
    client.initialize_user(&user1);
    client.deposit_flexi(&user1, &10_000);

    let lock_id = client.create_lock_save(&user1, &10_000, &30);
    client.route_lock_to_strategy(&user1, &lock_id, &strategy_id, &10_000);

    // 2. Trigger Emergency Withdraw (Governance action affecting Nestera lock_save)
    let withdrawn = client.emergency_withdraw(&admin, &user1, &PlanType::Lock(lock_id), &lock_id);
    assert_eq!(withdrawn, 10_000); // 10_000 lock amount

    // 3. Ensure plan is disabled & withdrawn
    assert!(client.is_strategy_disabled(&PlanType::Lock(lock_id), &lock_id));

    let res = client.try_withdraw_lock_save(&user1, &lock_id);
    assert!(res.is_err(), "already withdrawn");
}
