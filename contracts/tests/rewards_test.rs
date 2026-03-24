#![cfg(test)]

use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Events},
    Address, BytesN, Env, IntoVal, Symbol,
};
use Nestera::{
    rewards::{BonusAwarded, PointsAwarded, StreakUpdated},
    NesteraContract, NesteraContractClient,
};

fn create_test_env() -> (Env, NesteraContractClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let admin_pk = BytesN::from_array(&env, &[0u8; 32]);
    client.initialize(&admin, &admin_pk);

    let user = Address::generate(&env);
    client.init_user(&user);

    (env, client, admin, user)
}

fn setup_rewards_config(_env: &Env, client: &NesteraContractClient, admin: &Address) {
    client.init_rewards_config(
        admin, &10,        // points_per_token
        &2000,      // streak_bonus_bps (20%)
        &1000,      // long_lock_bonus_bps (10%)
        &100,       // goal_completion_bonus
        &true,      // enabled
        &0,         // min_deposit_for_rewards
        &0,         // action_cooldown_seconds
        &1_000_000, // max_daily_points
        &10_000,    // max_streak_multiplier (100%)
    );
}

#[test]
fn test_points_awarded_event() {
    let (env, client, admin, user) = create_test_env();
    setup_rewards_config(&env, &client, &admin);

    client.deposit_flexi(&user, &100);

    let events = env.events().all();
    let rewards_events: Vec<_> = events
        .iter()
        .filter(|e| {
            e.0 == client.address
                && e.1
                    == (
                        symbol_short!("rewards"),
                        symbol_short!("awarded"),
                        user.clone(),
                    )
                        .into_val(&env)
        })
        .collect();

    assert!(!rewards_events.is_empty());
    let last_event = rewards_events.last().unwrap();
    let event_data: PointsAwarded = last_event.2.clone().into_val(&env);

    assert_eq!(event_data.user, user);
    assert_eq!(event_data.amount, 1000); // 100 * 10
}

#[test]
fn test_streak_updated_event() {
    let (env, client, admin, user) = create_test_env();
    setup_rewards_config(&env, &client, &admin);

    client.deposit_flexi(&user, &100);

    let events = env.events().all();
    let streak_events: Vec<_> = events
        .iter()
        .filter(|e| {
            e.0 == client.address
                && e.1
                    == (
                        symbol_short!("rewards"),
                        symbol_short!("streak"),
                        user.clone(),
                    )
                        .into_val(&env)
        })
        .collect();

    assert!(!streak_events.is_empty());
    let event_data: StreakUpdated = streak_events.first().unwrap().2.clone().into_val(&env);

    assert_eq!(event_data.user, user);
    assert_eq!(event_data.streak, 1);
}

#[test]
fn test_bonus_awarded_streak_event() {
    let (env, client, admin, user) = create_test_env();
    setup_rewards_config(&env, &client, &admin);

    // Initial streak
    client.deposit_flexi(&user, &100); // streak 1
    client.deposit_flexi(&user, &100); // streak 2
    client.deposit_flexi(&user, &100); // streak 3

    let events = env.events().all();
    let bonus_events: Vec<_> = events
        .iter()
        .filter(|e| {
            e.0 == client.address
                && e.1
                    == (
                        symbol_short!("rewards"),
                        symbol_short!("bonus"),
                        user.clone(),
                    )
                        .into_val(&env)
        })
        .collect();

    assert!(!bonus_events.is_empty());
    let event_data: BonusAwarded = bonus_events.first().unwrap().2.clone().into_val(&env);

    assert_eq!(event_data.user, user);
    assert_eq!(event_data.bonus_type, Symbol::new(&env, "streak"));
    assert_eq!(event_data.amount, 200); // 1000 base * 20% bonus = 200
}
