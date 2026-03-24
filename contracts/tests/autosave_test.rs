#[cfg(test)]
mod autosave_tests {
    use soroban_sdk::{testutils::Address as _, Address, Env};
    use Nestera::{NesteraContract, NesteraContractClient};

    fn setup_test_contract() -> (Env, NesteraContractClient<'static>, Address) {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register(NesteraContract, ());
        let client = NesteraContractClient::new(&env, &contract_id);

        let user = Address::generate(&env);

        // Initialize user
        client.initialize_user(&user);

        (env, client, user)
    }

    #[test]
    fn test_create_autosave_success() {
        let (env, client, user) = setup_test_contract();

        let amount = 1000;
        let interval = 86400; // 1 day
        let start_time = env.ledger().timestamp();

        let result = client.create_autosave(&user, &amount, &interval, &start_time);
        assert_eq!(result, 1); // First schedule ID

        // Verify schedule was stored
        let schedules = client.get_user_autosaves(&user);
        assert_eq!(schedules.len(), 1);
        assert_eq!(schedules.get(0).unwrap(), 1);
    }

    #[test]
    fn test_create_autosave_zero_amount() {
        let (env, client, user) = setup_test_contract();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.create_autosave(&user, &0, &86400, &env.ledger().timestamp());
        }));
        assert!(result.is_err()); // Should panic with InvalidAmount
    }

    #[test]
    fn test_create_autosave_zero_interval() {
        let (env, client, user) = setup_test_contract();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.create_autosave(&user, &1000, &0, &env.ledger().timestamp());
        }));
        assert!(result.is_err()); // Should panic with InvalidTimestamp
    }

    #[test]
    fn test_create_autosave_user_not_found() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register(NesteraContract, ());
        let client = NesteraContractClient::new(&env, &contract_id);

        let user = Address::generate(&env); // Not initialized

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.create_autosave(&user, &1000, &86400, &env.ledger().timestamp());
        }));
        assert!(result.is_err()); // Should panic with UserNotFound
    }

    #[test]
    fn test_execute_autosave_success() {
        let (env, client, user) = setup_test_contract();

        let amount = 1000;
        let interval = 86400;
        let start_time = env.ledger().timestamp();

        let schedule_id = client.create_autosave(&user, &amount, &interval, &start_time);

        // Get initial balance
        let initial_balance = client.get_flexi_balance(&user);

        // Execute the schedule
        client.execute_autosave(&schedule_id);

        // Verify balance increased
        let new_balance = client.get_flexi_balance(&user);
        assert_eq!(new_balance, initial_balance + amount);
    }

    #[test]
    fn test_execute_autosave_before_due_time() {
        let (env, client, user) = setup_test_contract();

        let amount = 1000;
        let interval = 86400;
        let start_time = env.ledger().timestamp() + 10000; // Future time

        let schedule_id = client.create_autosave(&user, &amount, &interval, &start_time);

        // Try to execute before due time
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.execute_autosave(&schedule_id);
        }));
        assert!(result.is_err()); // Should panic with InvalidTimestamp
    }

    #[test]
    fn test_cancel_autosave_success() {
        let (env, client, user) = setup_test_contract();

        let schedule_id = client.create_autosave(&user, &1000, &86400, &env.ledger().timestamp());

        // Cancel the schedule
        client.cancel_autosave(&user, &schedule_id);

        // Try to execute cancelled schedule - should fail
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.execute_autosave(&schedule_id);
        }));
        assert!(result.is_err());
    }

    #[test]
    fn test_cancel_autosave_unauthorized() {
        let (env, client, user) = setup_test_contract();

        let schedule_id = client.create_autosave(&user, &1000, &86400, &env.ledger().timestamp());

        let other_user = Address::generate(&env);
        client.initialize_user(&other_user);

        // Try to cancel someone else's schedule
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.cancel_autosave(&other_user, &schedule_id);
        }));
        assert!(result.is_err()); // Should panic with Unauthorized
    }

    #[test]
    fn test_get_user_autosaves() {
        let (env, client, user) = setup_test_contract();

        let start_time = env.ledger().timestamp();

        let id1 = client.create_autosave(&user, &1000, &86400, &start_time);
        let id2 = client.create_autosave(&user, &2000, &172800, &start_time);

        let schedules = client.get_user_autosaves(&user);
        assert_eq!(schedules.len(), 2);
        assert_eq!(schedules.get(0).unwrap(), id1);
        assert_eq!(schedules.get(1).unwrap(), id2);
    }

    #[test]
    fn test_execute_cancelled_schedule() {
        let (env, client, user) = setup_test_contract();

        let schedule_id = client.create_autosave(&user, &1000, &86400, &env.ledger().timestamp());

        // Cancel the schedule
        client.cancel_autosave(&user, &schedule_id);

        // Try to execute - should fail
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.execute_autosave(&schedule_id);
        }));
        assert!(result.is_err()); // Should panic with InvalidPlanConfig
    }

    // ========== Batch Execution Tests ==========

    #[test]
    fn test_batch_execute_multiple_due_schedules() {
        let (env, client, user) = setup_test_contract();

        let start_time = env.ledger().timestamp(); // immediately due

        // Create three due schedules
        let id1 = client.create_autosave(&user, &500, &86400, &start_time);
        let id2 = client.create_autosave(&user, &300, &86400, &start_time);
        let id3 = client.create_autosave(&user, &200, &86400, &start_time);

        let schedule_ids = soroban_sdk::vec![&env, id1, id2, id3];
        let results = client.execute_due_autosaves(&schedule_ids);

        // All should succeed
        assert_eq!(results.len(), 3);
        assert!(results.get(0).unwrap());
        assert!(results.get(1).unwrap());
        assert!(results.get(2).unwrap());

        // Verify total Flexi balance = 500 + 300 + 200 = 1000
        let balance = client.get_flexi_balance(&user);
        assert_eq!(balance, 1000);
    }

    #[test]
    fn test_batch_execute_not_due_schedules_skipped() {
        let (env, client, user) = setup_test_contract();

        let future_time = env.ledger().timestamp() + 100_000; // far in the future

        let id1 = client.create_autosave(&user, &1000, &86400, &future_time);
        let id2 = client.create_autosave(&user, &2000, &86400, &future_time);

        let schedule_ids = soroban_sdk::vec![&env, id1, id2];
        let results = client.execute_due_autosaves(&schedule_ids);

        // Both should be skipped (not due)
        assert_eq!(results.len(), 2);
        assert!(!results.get(0).unwrap());
        assert!(!results.get(1).unwrap());

        // Balance should remain 0
        let balance = client.get_flexi_balance(&user);
        assert_eq!(balance, 0);
    }

    #[test]
    fn test_batch_execute_invalid_ids_handled_safely() {
        let (env, client, _user) = setup_test_contract();

        // Use IDs that don't exist
        let schedule_ids = soroban_sdk::vec![&env, 999u64, 888u64, 777u64];
        let results = client.execute_due_autosaves(&schedule_ids);

        // All should be false (not found)
        assert_eq!(results.len(), 3);
        assert!(!results.get(0).unwrap());
        assert!(!results.get(1).unwrap());
        assert!(!results.get(2).unwrap());
    }

    #[test]
    fn test_batch_execute_inactive_schedules_skipped() {
        let (env, client, user) = setup_test_contract();

        let start_time = env.ledger().timestamp();

        let id1 = client.create_autosave(&user, &1000, &86400, &start_time);
        let id2 = client.create_autosave(&user, &2000, &86400, &start_time);

        // Cancel id1 (makes it inactive)
        client.cancel_autosave(&user, &id1);

        let schedule_ids = soroban_sdk::vec![&env, id1, id2];
        let results = client.execute_due_autosaves(&schedule_ids);

        // id1 should be false (inactive), id2 should be true (due and active)
        assert_eq!(results.len(), 2);
        assert!(!results.get(0).unwrap());
        assert!(results.get(1).unwrap());

        // Only id2's 2000 should have been deposited
        let balance = client.get_flexi_balance(&user);
        assert_eq!(balance, 2000);
    }

    #[test]
    fn test_batch_execute_partial_success() {
        let (env, client, user) = setup_test_contract();

        let start_time = env.ledger().timestamp();
        let future_time = env.ledger().timestamp() + 100_000;

        // id1: due and active -> should succeed
        let id1 = client.create_autosave(&user, &500, &86400, &start_time);
        // id2: not due -> should be skipped
        let id2 = client.create_autosave(&user, &300, &86400, &future_time);
        // id3: due and active -> should succeed
        let id3 = client.create_autosave(&user, &200, &86400, &start_time);
        // id4: cancelled -> should be skipped
        let id4 = client.create_autosave(&user, &1000, &86400, &start_time);
        client.cancel_autosave(&user, &id4);

        // Also include a non-existent ID
        let fake_id: u64 = 999;

        let schedule_ids = soroban_sdk::vec![&env, id1, id2, id3, id4, fake_id];
        let results = client.execute_due_autosaves(&schedule_ids);

        assert_eq!(results.len(), 5);
        assert!(results.get(0).unwrap()); // id1: due, active -> executed
        assert!(!results.get(1).unwrap()); // id2: not due -> skipped
        assert!(results.get(2).unwrap()); // id3: due, active -> executed
        assert!(!results.get(3).unwrap()); // id4: inactive -> skipped
        assert!(!results.get(4).unwrap()); // fake_id: not found -> skipped

        // Only id1 (500) and id3 (200) executed -> balance = 700
        let balance = client.get_flexi_balance(&user);
        assert_eq!(balance, 700);
    }

    #[test]
    fn test_batch_execute_updates_next_execution_time() {
        let (env, client, user) = setup_test_contract();

        let start_time = env.ledger().timestamp();
        let interval = 86400u64;

        let id1 = client.create_autosave(&user, &1000, &interval, &start_time);

        let schedule_ids = soroban_sdk::vec![&env, id1];
        let results = client.execute_due_autosaves(&schedule_ids);

        assert!(results.get(0).unwrap());

        // Verify next_execution_time was advanced
        let schedule = client.get_autosave(&id1).unwrap();
        assert_eq!(schedule.next_execution_time, start_time + interval);
    }

    #[test]
    fn test_batch_execute_empty_list() {
        let (env, client, _user) = setup_test_contract();

        let schedule_ids: soroban_sdk::Vec<u64> = soroban_sdk::vec![&env];
        let results = client.execute_due_autosaves(&schedule_ids);

        // Should return empty results
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_batch_execute_flexi_balances_correct_multi_user() {
        let (env, client, user1) = setup_test_contract();

        let user2 = Address::generate(&env);
        client.initialize_user(&user2);

        let start_time = env.ledger().timestamp();

        // user1 schedules
        let id1 = client.create_autosave(&user1, &500, &86400, &start_time);
        // user2 schedules
        let id2 = client.create_autosave(&user2, &800, &86400, &start_time);

        let schedule_ids = soroban_sdk::vec![&env, id1, id2];
        let results = client.execute_due_autosaves(&schedule_ids);

        assert!(results.get(0).unwrap());
        assert!(results.get(1).unwrap());

        // Verify per-user Flexi balances
        assert_eq!(client.get_flexi_balance(&user1), 500);
        assert_eq!(client.get_flexi_balance(&user2), 800);
    }
}
