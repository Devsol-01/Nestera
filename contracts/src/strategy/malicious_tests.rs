use crate::strategy::interface::YieldStrategy;
use crate::{NesteraContract, NesteraContractClient};
use soroban_sdk::{contract, contractimpl, testutils::Address as _, Address, BytesN, Env, Symbol};

#[contract]
pub struct MaliciousStrategy;

#[contractimpl]
impl YieldStrategy for MaliciousStrategy {
    fn strategy_deposit(env: Env, _from: Address, _amount: i128) -> i128 {
        let nestera_id = env
            .storage()
            .instance()
            .get::<Symbol, Address>(&Symbol::new(&env, "nestera"))
            .unwrap();
        let client = NesteraContractClient::new(&env, &nestera_id);
        let user = Address::generate(&env);

        // Attempt reentrancy
        let res = client.try_deposit_flexi(&user, &100);

        // If it didn't fail with ReentrancyDetected, we "failed" our test of the guard
        if let Ok(Ok(())) = res.as_ref() {
            panic!("Reentrancy was not blocked! Got: {:?}", res);
        }
        100 // Correctly blocked
    }

    fn strategy_withdraw(env: Env, _to: Address, _amount: i128) -> i128 {
        let nestera_id = env
            .storage()
            .instance()
            .get::<Symbol, Address>(&Symbol::new(&env, "nestera"))
            .unwrap();
        let client = NesteraContractClient::new(&env, &nestera_id);
        let user = Address::generate(&env);

        // Attempt reentrancy
        let res = client.try_withdraw_flexi(&user, &100);

        if let Ok(Ok(())) = res.as_ref() {
            panic!("Reentrancy was not blocked! Got: {:?}", res);
        }
        100
    }

    fn strategy_harvest(env: Env, _to: Address) -> i128 {
        let nestera_id = env
            .storage()
            .instance()
            .get::<Symbol, Address>(&Symbol::new(&env, "nestera"))
            .unwrap();
        let client = NesteraContractClient::new(&env, &nestera_id);
        let strategy_addr = env.current_contract_address();
        let admin = Address::generate(&env);

        // Attempt reentrancy
        let res = client.try_harvest_strategy(&admin, &strategy_addr);

        if res.is_ok() && res.unwrap().is_ok() {
            panic!("Reentrancy was not blocked! Got: {:?}", res);
        }
        100
    }

    fn strategy_balance(_env: Env, _addr: Address) -> i128 {
        1000
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    fn setup(env: &Env) -> (NesteraContractClient<'static>, Address) {
        let nestera_id = env.register(NesteraContract, ());
        let nestera_client = NesteraContractClient::new(env, &nestera_id);
        let admin = Address::generate(env);
        let admin_pk = BytesN::from_array(env, &[1u8; 32]);
        nestera_client.initialize(&admin, &admin_pk);

        let malicious_id = env.register(MaliciousStrategy, ());
        env.as_contract(&malicious_id, || {
            env.storage()
                .instance()
                .set(&Symbol::new(env, "nestera"), &nestera_id);
        });

        nestera_client.register_strategy(&admin, &malicious_id, &1);
        (nestera_client, malicious_id)
    }

    #[test]
    fn test_reentrancy_blocked_on_route_deposit() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, malicious_id) = setup(&env);

        let user = Address::generate(&env);
        client.init_user(&user);
        let lock_id = client.create_lock_save(&user, &1000, &3600);

        // This will call strategy_deposit which will try to re-enter
        // If reentrancy is NOT blocked, strategy_deposit will panic, and this will fail.
        // Actually, our MaliciousStrategy panics if it's NOT blocked.
        // So success here means it WAS blocked.
        let result = client.try_route_lock_to_strategy(&user, &lock_id, &malicious_id, &500);
        assert!(result.is_ok());
    }

    #[test]
    fn test_reentrancy_blocked_on_withdraw() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, malicious_id) = setup(&env);

        let user = Address::generate(&env);
        client.init_user(&user);
        let lock_id = client.create_lock_save(&user, &1000, &3600);
        client.route_lock_to_strategy(&user, &lock_id, &malicious_id, &500);

        // This will call strategy_withdraw which will try to re-enter
        let result = client.try_withdraw_lock_strategy(&user, &lock_id, &user);
        assert!(result.is_ok());
    }

    #[test]
    fn test_reentrancy_blocked_on_harvest() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, malicious_id) = setup(&env);

        let user = Address::generate(&env);
        client.init_user(&user);
        let lock_id = client.create_lock_save(&user, &1000, &3600);
        client.route_lock_to_strategy(&user, &lock_id, &malicious_id, &500);

        let admin = client.get_config().admin;
        let result = client.try_harvest_strategy(&admin, &malicious_id);
        assert!(result.is_ok());
    }
}
