use crate::{NesteraContract, NesteraContractClient, SavingsError};
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env};

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

#[test]
fn test_default_rates_are_zero() {
    let (_env, client, _admin) = setup();

    // Default rates should be 0
    assert_eq!(client.get_flexi_rate(), 0);
    assert_eq!(client.get_goal_rate(), 0);
    assert_eq!(client.get_group_rate(), 0);
    // Lock rate for random duration should be error (PlanNotFound) if not set?
    // In rates.rs: get_lock_rate -> ok_or(SavingsError::PlanNotFound)
    // Actually, "PlanNotFound" is maybe not the best error for "RateNotFound", but it's what I used.
    let res = client.try_get_lock_rate(&30);
    assert_eq!(res.unwrap_err(), Ok(SavingsError::PlanNotFound));
}

#[test]
fn test_admin_can_set_rates() {
    let (env, client, admin) = setup();

    env.mock_all_auths();

    // Set Flexi Rate to 500 (5%)
    assert!(client.try_set_flexi_rate(&admin, &500).is_ok());
    assert_eq!(client.get_flexi_rate(), 500);

    // Set Goal Rate
    assert!(client.try_set_goal_rate(&admin, &600).is_ok());
    assert_eq!(client.get_goal_rate(), 600);

    // Set Group Rate
    assert!(client.try_set_group_rate(&admin, &700).is_ok());
    assert_eq!(client.get_group_rate(), 700);

    // Set Lock Rate for 30 days
    assert!(client.try_set_lock_rate(&admin, &30, &800).is_ok());
    assert_eq!(client.get_lock_rate(&30), 800);

    // Verify independent lock rates
    assert!(client.try_set_lock_rate(&admin, &60, &900).is_ok());
    assert_eq!(client.get_lock_rate(&60), 900);
    assert_eq!(client.get_lock_rate(&30), 800); // 30 days unchanged
}

#[test]
fn test_non_admin_cannot_set_rates() {
    let (env, client, _admin) = setup();
    let user = Address::generate(&env);

    env.mock_all_auths();

    // Try set flexi rate
    let res = client.try_set_flexi_rate(&user, &500);
    assert!(res.is_err());

    // Try set goal rate
    let res = client.try_set_goal_rate(&user, &500);
    assert!(res.is_err());

    // Try set group rate
    let res = client.try_set_group_rate(&user, &500);
    assert!(res.is_err());

    // Try set lock rate
    let res = client.try_set_lock_rate(&user, &30, &500);
    assert!(res.is_err());
}

#[test]
fn test_calculate_flexi_interest_logic() {
    let balance = 1_000_000; // 1M
    let rate = 500; // 5%
    let duration = 365 * 24 * 60 * 60; // 1 year

    let interest = crate::rates::calculate_flexi_interest(balance, rate, duration);
    // 1M * 5% = 50,000
    // Logic: (1M * 500 * duration) / (10000 * duration) = 50,000
    assert_eq!(interest, 50_000);

    // Half year
    let interest_half = crate::rates::calculate_flexi_interest(balance, rate, duration / 2);
    assert_eq!(interest_half, 25_000);
}

#[test]
fn test_calculate_lock_interest_logic() {
    let amount = 1_000_000;
    let rate = 500; // 5% flat return?

    let interest = crate::rates::calculate_lock_interest(amount, rate);
    assert_eq!(interest, 50_000);
}

#[test]
fn test_invalid_rates() {
    let (env, client, admin) = setup();
    env.mock_all_auths();

    // Try set negative rate
    let res = client.try_set_flexi_rate(&admin, &-100);
    assert_eq!(res.unwrap_err(), Ok(SavingsError::InvalidInterestRate));
}
