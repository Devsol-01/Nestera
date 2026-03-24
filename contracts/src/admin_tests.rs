use crate::{NesteraContract, NesteraContractClient, SavingsError};
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env}; // import Error, InvokeError, symbol when necessary

fn setup() -> (Env, NesteraContractClient<'static>, Address) {
    let env = Env::default();
    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    // Fixed: Standard 32-byte array for admin public key simulation
    let admin_pk = BytesN::from_array(&env, &[1u8; 32]);

    env.mock_all_auths();
    // Assuming initialize returns Result now
    client.initialize(&admin, &admin_pk);

    (env, client, admin)
}

/// Helper for functions that do NOT return Result in the contract (they panic)
// fn assert_panic_error(err: Result<Error, InvokeError>, expected: SavingsError) {
//     assert_eq!(err, Ok(Error::from_contract_error(expected as u32)));
// }

// /// Helper for functions that DO return Result<T, SavingsError> in the contract
// fn assert_savings_error(
//     err: Result<Result<u64, soroban_sdk::Val>, Result<SavingsError, InvokeError>>,
//     expected: SavingsError,
// ) {
//     match err {
//         Err(Ok(actual_error)) => assert_eq!(actual_error, expected),
//         _ => panic!("Expected SavingsError: {:?}, but got {:?}", expected, err),
//     }
// }

// Overload-like helpers for different return types (u64 vs i128 vs ())
// If you have mixed return types, you may need a more generic match or individual helpers

#[test]
fn non_admin_cannot_pause_or_unpause() {
    let (env, client, _admin) = setup();
    let non_admin = Address::generate(&env);

    env.mock_all_auths();

    // try_pause returns Result<Result<(), ...>, Result<SavingsError, ...>>
    match client.try_pause(&non_admin) {
        Err(Ok(e)) => assert_eq!(e, SavingsError::Unauthorized),
        _ => panic!("Expected Unauthorized error"),
    }
}

#[test]
fn paused_blocks_write_paths() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    env.mock_all_auths();
    assert!(client.try_pause(&admin).is_ok());

    // For functions returning Result<(), SavingsError>
    match client.try_initialize_user(&user) {
        Err(Ok(e)) => assert_eq!(e, SavingsError::ContractPaused),
        _ => panic!("Expected ContractPaused"),
    }

    // For functions returning Result<u64, SavingsError>
    match client.try_create_savings_plan(&user, &crate::storage_types::PlanType::Flexi, &100) {
        Err(Ok(e)) => assert_eq!(e, SavingsError::ContractPaused),
        _ => panic!("Expected ContractPaused"),
    }

    // For functions returning Result<i128, SavingsError>
    match client.try_withdraw_flexi(&user, &5) {
        Err(Ok(e)) => assert_eq!(e, SavingsError::ContractPaused),
        _ => panic!("Expected ContractPaused"),
    }

    // Repeat the match pattern for other calls...
}

#[test]
fn admin_can_set_early_break_fee_and_recipient() {
    let (env, client, _admin) = setup();
    let treasury = Address::generate(&env);

    env.mock_all_auths();

    // If these return Result<(), SavingsError>, use .unwrap()
    // If they return (), remove the .unwrap()
    client.set_fee_recipient(&treasury);
    assert_eq!(client.get_fee_recipient().unwrap(), treasury);

    client.set_early_break_fee_bps(&500);
    assert_eq!(client.get_early_break_fee_bps(), 500);

    // This handles the Result returned by the 'try_' version
    let result = client.try_set_early_break_fee_bps(&10_001);

    match result {
        Err(Ok(e)) => assert_eq!(e, SavingsError::InvalidAmount),
        _ => panic!("Expected InvalidFeeBps error, got {:?}", result),
    }
}
