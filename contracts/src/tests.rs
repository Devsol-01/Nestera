#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    #[test]
    fn test_strategy_performance_tracking() {
        let env = Env::default();
        let strategy_id = 1;

        // Simulate deposits
        NesteraContract::deposit(env.clone(), strategy_id, 1000);
        NesteraContract::deposit(env.clone(), strategy_id, 2000);

        // Simulate withdrawals
        NesteraContract::withdraw(env.clone(), strategy_id, 500);

        // Simulate harvests
        NesteraContract::harvest(env.clone(), strategy_id);

        // Verify performance metrics
        let performance = NesteraContract::get_strategy_performance(&env, strategy_id);
        assert_eq!(performance.total_deposited, 3000);
        assert_eq!(performance.total_withdrawn, 500);
        assert!(performance.total_harvested > 0); // Placeholder check
    }

    #[test]
    fn test_reentrancy_protection() {
        let env = Env::default();

        // Acquire reentrancy guard
        assert!(crate::security::acquire_reentrancy_guard(&env).is_ok());

        // Attempt to acquire again should fail
        assert!(crate::security::acquire_reentrancy_guard(&env).is_err());

        // Release reentrancy guard
        crate::security::release_reentrancy_guard(&env);

        // Should be able to acquire again
        assert!(crate::security::acquire_reentrancy_guard(&env).is_ok());
    }
}