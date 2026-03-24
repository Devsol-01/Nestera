#[cfg(test)]
mod execution_tests {
    use crate::governance::ProposalAction;
    use crate::rewards::storage_types::RewardsConfig;
    use crate::{NesteraContract, NesteraContractClient, PlanType};
    use soroban_sdk::{
        testutils::{Address as _, Ledger},
        Address, BytesN, Env, String,
    };

    fn setup_contract() -> (Env, NesteraContractClient<'static>, Address) {
        let env = Env::default();
        let contract_id = env.register(NesteraContract, ());
        let client = NesteraContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let admin_pk = BytesN::from_array(&env, &[1u8; 32]);

        env.mock_all_auths();
        client.initialize(&admin, &admin_pk);

        let config = RewardsConfig {
            points_per_token: 10,
            streak_bonus_bps: 0,
            long_lock_bonus_bps: 0,
            goal_completion_bonus: 0,
            enabled: true,
            min_deposit_for_rewards: 0,
            action_cooldown_seconds: 0,
            max_daily_points: 1_000_000,
            max_streak_multiplier: 10_000,
        };
        client.initialize_rewards_config(&config);

        (env, client, admin)
    }

    fn setup_with_voted_proposal() -> (Env, NesteraContractClient<'static>, Address, u64) {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        client.init_voting_config(&admin, &5000, &604800, &86400, &100, &10_000);

        let creator = Address::generate(&env);
        let description = String::from_str(&env, "Test proposal");

        client.initialize_user(&creator);
        let _ = client.create_savings_plan(&creator, &PlanType::Flexi, &1000); // Meets threshold

        let action = ProposalAction::SetFlexiRate(500);
        let proposal_id = client
            .try_create_action_proposal(&creator, &description, &action)
            .unwrap()
            .unwrap();

        // Create voters with voting power
        let voter1 = Address::generate(&env);
        let voter2 = Address::generate(&env);

        client.initialize_user(&voter1);
        client.initialize_user(&voter2);

        let _ = client.create_savings_plan(&voter1, &PlanType::Flexi, &3000);
        let _ = client.create_savings_plan(&voter2, &PlanType::Flexi, &2000);

        // Vote for the proposal
        client.vote(&proposal_id, &1, &voter1);
        client.vote(&proposal_id, &1, &voter2);

        (env, client, admin, proposal_id)
    }

    #[test]
    fn test_queue_proposal_success() {
        let (env, client, _admin, proposal_id) = setup_with_voted_proposal();
        env.mock_all_auths();

        // Advance time past voting period
        env.ledger().with_mut(|li| {
            li.timestamp += 604800 + 1;
        });

        let result = client.try_queue_proposal(&proposal_id);
        assert!(result.is_ok());

        let proposal = client.get_action_proposal(&proposal_id).unwrap();
        assert!(proposal.queued_time > 0);
    }

    #[test]
    fn test_queue_proposal_before_voting_ends() {
        let (env, client, _admin, proposal_id) = setup_with_voted_proposal();
        env.mock_all_auths();

        let result = client.try_queue_proposal(&proposal_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_queue_proposal_failed_vote() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        client.init_voting_config(&admin, &5000, &604800, &86400, &100, &10_000);

        let creator = Address::generate(&env);
        let description = String::from_str(&env, "Test proposal");

        client.initialize_user(&creator);
        let _ = client.create_savings_plan(&creator, &PlanType::Flexi, &1000);

        let action = ProposalAction::SetFlexiRate(500);
        let proposal_id = client
            .try_create_action_proposal(&creator, &description, &action)
            .unwrap()
            .unwrap();

        // Vote against
        let voter = Address::generate(&env);
        client.initialize_user(&voter);
        let _ = client.create_savings_plan(&voter, &PlanType::Flexi, &1000);
        client.vote(&proposal_id, &2, &voter);

        // Advance time
        env.ledger().with_mut(|li| {
            li.timestamp += 604800 + 1;
        });

        let result = client.try_queue_proposal(&proposal_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_execute_proposal_success() {
        let (env, client, _admin, proposal_id) = setup_with_voted_proposal();
        env.mock_all_auths();

        // Advance time past voting period
        env.ledger().with_mut(|li| {
            li.timestamp += 604800 + 1;
        });

        client.queue_proposal(&proposal_id);

        // Advance time past timelock
        env.ledger().with_mut(|li| {
            li.timestamp += 86400 + 1;
        });

        let result = client.try_execute_proposal(&proposal_id);
        assert!(result.is_ok());

        let proposal = client.get_action_proposal(&proposal_id).unwrap();
        assert!(proposal.executed);

        // Verify action was executed
        assert_eq!(client.get_flexi_rate(), 500);
    }

    #[test]
    fn test_execute_proposal_before_timelock() {
        let (env, client, _admin, proposal_id) = setup_with_voted_proposal();
        env.mock_all_auths();

        // Advance time past voting period
        env.ledger().with_mut(|li| {
            li.timestamp += 604800 + 1;
        });

        client.queue_proposal(&proposal_id);

        // Try to execute before timelock
        let result = client.try_execute_proposal(&proposal_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_execute_proposal_not_queued() {
        let (env, client, _admin, proposal_id) = setup_with_voted_proposal();
        env.mock_all_auths();

        // Advance time past voting period
        env.ledger().with_mut(|li| {
            li.timestamp += 604800 + 1;
        });

        // Try to execute without queueing
        let result = client.try_execute_proposal(&proposal_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_cannot_queue_twice() {
        let (env, client, _admin, proposal_id) = setup_with_voted_proposal();
        env.mock_all_auths();

        // Advance time past voting period
        env.ledger().with_mut(|li| {
            li.timestamp += 604800 + 1;
        });

        client.queue_proposal(&proposal_id);

        let result = client.try_queue_proposal(&proposal_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_cannot_execute_twice() {
        let (env, client, _admin, proposal_id) = setup_with_voted_proposal();
        env.mock_all_auths();

        // Advance time past voting period
        env.ledger().with_mut(|li| {
            li.timestamp += 604800 + 1;
        });

        client.queue_proposal(&proposal_id);

        // Advance time past timelock
        env.ledger().with_mut(|li| {
            li.timestamp += 86400 + 1;
        });

        client.execute_proposal(&proposal_id);

        let result = client.try_execute_proposal(&proposal_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_full_governance_flow() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        // Setup governance
        client.init_voting_config(&admin, &5000, &604800, &86400, &100, &10_000);

        // Create proposal
        let creator = Address::generate(&env);
        let description = String::from_str(&env, "Change flexi rate");

        client.initialize_user(&creator);
        let _ = client.create_savings_plan(&creator, &PlanType::Flexi, &1000);

        let action = ProposalAction::SetFlexiRate(750);
        let proposal_id = client
            .try_create_action_proposal(&creator, &description, &action)
            .unwrap()
            .unwrap();

        // Vote
        let voter1 = Address::generate(&env);
        let voter2 = Address::generate(&env);
        client.initialize_user(&voter1);
        client.initialize_user(&voter2);
        let _ = client.create_savings_plan(&voter1, &PlanType::Flexi, &4000);
        let _ = client.create_savings_plan(&voter2, &PlanType::Flexi, &3000);

        client.vote(&proposal_id, &1, &voter1);
        client.vote(&proposal_id, &1, &voter2);

        // Wait for voting to end
        env.ledger().with_mut(|li| {
            li.timestamp += 604800 + 1;
        });

        // Queue
        client.queue_proposal(&proposal_id);

        // Wait for timelock
        env.ledger().with_mut(|li| {
            li.timestamp += 86400 + 1;
        });

        // Execute
        client.execute_proposal(&proposal_id);

        // Verify
        assert_eq!(client.get_flexi_rate(), 750);
        let proposal = client.get_action_proposal(&proposal_id).unwrap();
        assert!(proposal.executed);
    }

    #[test]
    fn test_execute_pause_action() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        client.init_voting_config(&admin, &5000, &604800, &86400, &100, &10_000);

        let creator = Address::generate(&env);
        let description = String::from_str(&env, "Pause contract");

        client.initialize_user(&creator);
        let _ = client.create_savings_plan(&creator, &PlanType::Flexi, &1000);

        let action = ProposalAction::PauseContract;
        let proposal_id = client
            .try_create_action_proposal(&creator, &description, &action)
            .unwrap()
            .unwrap();

        let voter = Address::generate(&env);
        client.initialize_user(&voter);
        let _ = client.create_savings_plan(&voter, &PlanType::Flexi, &5000);
        client.vote(&proposal_id, &1, &voter);

        env.ledger().with_mut(|li| {
            li.timestamp += 604800 + 1;
        });
        client.queue_proposal(&proposal_id);

        env.ledger().with_mut(|li| {
            li.timestamp += 86400 + 1;
        });
        client.execute_proposal(&proposal_id);

        assert!(client.is_paused());
    }
}
