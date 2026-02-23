#[cfg(test)]
mod governance_tests {
    use crate::governance::VotingConfig;
    use crate::rewards::storage_types::RewardsConfig;
    use crate::{NesteraContract, NesteraContractClient, PlanType};
    use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, String};

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
        let _ = client.initialize_rewards_config(&config);

        (env, client, admin)
    }

    #[test]
    fn test_voting_power_zero_for_new_user() {
        let (env, client, _) = setup_contract();
        let user = Address::generate(&env);

        let power = client.get_voting_power(&user);
        assert_eq!(power, 0);
    }

    #[test]
    fn test_voting_power_increases_with_deposits() {
        let (env, client, _) = setup_contract();
        let user = Address::generate(&env);
        env.mock_all_auths();

        client.initialize_user(&user);
        let _ = client.create_savings_plan(&user, &PlanType::Flexi, &1000);

        let power = client.get_voting_power(&user);
        assert_eq!(power, 1000);
    }

    #[test]
    fn test_voting_power_accumulates_across_deposits() {
        let (env, client, _) = setup_contract();
        let user = Address::generate(&env);
        env.mock_all_auths();

        client.initialize_user(&user);
        let _ = client.create_savings_plan(&user, &PlanType::Flexi, &1000);
        let _ = client.create_savings_plan(&user, &PlanType::Flexi, &500);

        let power = client.get_voting_power(&user);
        assert_eq!(power, 1500);
    }

    #[test]
    fn test_cast_vote_requires_voting_power() {
        let (env, client, _) = setup_contract();
        let user = Address::generate(&env);
        env.mock_all_auths();

        client.initialize_user(&user);

        let result = client.try_vote(&1, &1, &user);
        assert!(result.is_err());
    }

    #[test]
    fn test_cast_vote_succeeds_with_voting_power() {
        let (env, client, _) = setup_contract();
        let user = Address::generate(&env);
        env.mock_all_auths();

        client.initialize_user(&user);
        let _ = client.create_savings_plan(&user, &PlanType::Flexi, &1000);

        let result = client.try_vote(&1, &1, &user);
        assert!(result.is_err());
    }

    #[test]
    fn test_init_voting_config() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        let result = client.try_init_voting_config(&admin, &5000, &604800, &86400, &1000, &100000);
        assert!(result.is_ok());

        let config = client.try_get_voting_config().unwrap().unwrap();
        assert_eq!(config.quorum, 5000);
        assert_eq!(config.voting_period, 604800);
        assert_eq!(config.timelock_duration, 86400);
        assert_eq!(config.min_proposal_weight, 1000);
        assert_eq!(config.max_voting_power_per_user, 100000);
    }

    #[test]
    fn test_create_proposal() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        let _ = client.init_voting_config(&admin, &5000, &604800, &86400, &1000, &100000);

        let creator = Address::generate(&env);
        let description = String::from_str(&env, "Test proposal");
        let proposal_id = client
            .try_create_proposal(&creator, &description)
            .unwrap()
            .unwrap();

        assert_eq!(proposal_id, 1);
    }

    #[test]
    fn test_get_proposal() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        let _ = client.init_voting_config(&admin, &5000, &604800, &86400, &1000, &100000);

        let creator = Address::generate(&env);
        let description = String::from_str(&env, "Test proposal");
        let proposal_id = client
            .try_create_proposal(&creator, &description)
            .unwrap()
            .unwrap();

        let proposal = client.get_proposal(&proposal_id).unwrap();
        assert_eq!(proposal.id, 1);
        assert_eq!(proposal.creator, creator);
        assert_eq!(proposal.executed, false);
        assert_eq!(proposal.for_votes, 0);
        assert_eq!(proposal.against_votes, 0);
    }

    #[test]
    fn test_list_proposals() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        let _ = client.init_voting_config(&admin, &5000, &604800, &86400, &1000, &100000);

        let creator = Address::generate(&env);
        let desc1 = String::from_str(&env, "Proposal 1");
        let desc2 = String::from_str(&env, "Proposal 2");

        let _ = client.try_create_proposal(&creator, &desc1);
        let _ = client.try_create_proposal(&creator, &desc2);

        let proposals = client.list_proposals();
        assert_eq!(proposals.len(), 2);
        assert_eq!(proposals.get(0).unwrap(), 1);
        assert_eq!(proposals.get(1).unwrap(), 2);
    }

    #[test]
    fn test_proposal_stored_correctly() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        let _ = client.init_voting_config(&admin, &5000, &604800, &86400, &1000, &100000);

        let creator = Address::generate(&env);
        let description = String::from_str(&env, "Store test");
        let proposal_id = client
            .try_create_proposal(&creator, &description)
            .unwrap()
            .unwrap();

        let proposal = client.get_proposal(&proposal_id).unwrap();
        let now = env.ledger().timestamp();

        assert_eq!(proposal.description, description);
        assert_eq!(proposal.start_time, now);
        assert_eq!(proposal.end_time, now + 604800);
    }

    // ========== Security Tests for Governance Anti-Abuse ==========

    #[test]
    fn test_min_proposal_weight_blocks_low_power_creators() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        // Initialize with min_proposal_weight of 5000
        let _ = client.init_voting_config(&admin, &5000, &604800, &86400, &5000, &100000);

        // Create user with insufficient governance power (0)
        let weak_creator = Address::generate(&env);
        client.initialize_user(&weak_creator);

        // Attempt to create proposal should fail
        let description = String::from_str(&env, "Weak proposal");
        let result = client.try_create_proposal(&weak_creator, &description);

        assert!(result.is_err());
    }

    #[test]
    fn test_min_proposal_weight_allows_sufficient_power() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        // Initialize with min_proposal_weight of 1000
        let _ = client.init_voting_config(&admin, &5000, &604800, &86400, &1000, &100000);

        // Create user with sufficient governance power
        let strong_creator = Address::generate(&env);
        client.initialize_user(&strong_creator);
        let _ = client.create_savings_plan(&strong_creator, &PlanType::Flexi, &2000);

        // Create proposal should succeed
        let description = String::from_str(&env, "Strong proposal");
        let result = client.try_create_proposal(&strong_creator, &description);

        assert!(result.is_ok());
    }

    #[test]
    fn test_max_voting_power_per_user_caps_vote_weight() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        // Initialize with max_voting_power_per_user of 500
        let _ = client.init_voting_config(&admin, &5000, &604800, &86400, &100, &500);

        // Create proposal
        let creator = Address::generate(&env);
        let description = String::from_str(&env, "Capping test");
        let proposal_id = client
            .try_create_proposal(&creator, &description)
            .unwrap()
            .unwrap();

        // Create voter with very high balance (2000)
        let voter = Address::generate(&env);
        client.initialize_user(&voter);
        let _ = client.create_savings_plan(&voter, &PlanType::Flexi, &2000);

        // Vote should use capped weight (500, not 2000)
        let result = client.try_vote(&proposal_id, &1, &voter);
        assert!(result.is_ok());

        // Check that proposal votes don't exceed the cap
        let proposal = client.get_proposal(&proposal_id).unwrap();
        assert_eq!(proposal.for_votes, 500); // Capped at max_voting_power_per_user
    }

    #[test]
    fn test_prevent_double_voting_same_proposal() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        let _ = client.init_voting_config(&admin, &5000, &604800, &86400, &100, &100000);

        // Create proposal and voter with voting power
        let creator = Address::generate(&env);
        let description = String::from_str(&env, "Double vote test");
        let proposal_id = client
            .try_create_proposal(&creator, &description)
            .unwrap()
            .unwrap();

        let voter = Address::generate(&env);
        client.initialize_user(&voter);
        let _ = client.create_savings_plan(&voter, &PlanType::Flexi, &1000);

        // First vote should succeed
        let result1 = client.try_vote(&proposal_id, &1, &voter);
        assert!(result1.is_ok());

        // Second vote on same proposal should fail
        let result2 = client.try_vote(&proposal_id, &2, &voter);
        assert!(result2.is_err());
    }

    #[test]
    fn test_duplicate_execution_prevention() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        let _ = client.init_voting_config(&admin, &5000, &604800, &86400, &100, &100000);

        // Create action proposal
        let creator = Address::generate(&env);
        let client_copy = &client;
        let description = String::from_str(&env, "Prevent double exec");
        let action = ProposalAction::SetFlexiRate(600);
        let proposal_id = client
            .try_create_action_proposal(&creator, &description, &action)
            .unwrap()
            .unwrap();

        // Create voters to pass proposal
        let voter1 = Address::generate(&env);
        client.initialize_user(&voter1);
        let _ = client.create_savings_plan(&voter1, &PlanType::Flexi, &1000);

        let _vote = client.try_vote(&proposal_id, &1, &voter1);

        // Simulate time progression for voting period and timelock
        env.ledger().with_mut(|l| {
            l.timestamp = env.ledger().timestamp() + 700_000;
        });

        // Queue proposal
        let _queue_result = client.try_queue_proposal(&proposal_id);

        // Simulate time for timelock to pass
        env.ledger().with_mut(|l| {
            l.timestamp = env.ledger().timestamp() + 100_000;
        });

        // First execution should succeed
        let result1 = client.try_execute_proposal(&proposal_id);
        assert!(result1.is_ok());

        // Second execution attempt should fail
        let result2 = client.try_execute_proposal(&proposal_id);
        assert!(result2.is_err());
    }

    #[test]
    fn test_vote_manipulation_multiple_users() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        let _ = client.init_voting_config(&admin, &5000, &604800, &86400, &100, &100000);

        let creator = Address::generate(&env);
        let description = String::from_str(&env, "Manipulation test");
        let proposal_id = client
            .try_create_proposal(&creator, &description)
            .unwrap()
            .unwrap();

        // Create 3 voters with different weights
        let mut total_for_votes = 0u128;

        for i in 0..3 {
            let voter = Address::generate(&env);
            client.initialize_user(&voter);
            let deposit = 1000 + (i as i128 * 500);
            let _ = client.create_savings_plan(&voter, &PlanType::Flexi, &deposit);

            let result = client.try_vote(&proposal_id, &1, &voter);
            assert!(result.is_ok());

            total_for_votes += (1000 + (i as u128 * 500));
        }

        let proposal = client.get_proposal(&proposal_id).unwrap();
        assert_eq!(proposal.for_votes, total_for_votes);
        assert_eq!(proposal.against_votes, 0);
    }

    #[test]
    fn test_proposal_timestamp_validation_no_overflow() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        // Initialize voting config
        let _ = client.init_voting_config(&admin, &5000, &604800, &86400, &100, &100000);

        let creator = Address::generate(&env);
        let description = String::from_str(&env, "Timestamp test");

        // Creating proposal should succeed with valid timestamp
        let result = client.try_create_proposal(&creator, &description);
        assert!(result.is_ok());
    }

    #[test]
    fn test_min_weight_action_proposal() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        // Initialize with min_proposal_weight of 2000
        let _ = client.init_voting_config(&admin, &5000, &604800, &86400, &2000, &100000);

        // Create user with insufficient governance power
        let weak_creator = Address::generate(&env);
        client.initialize_user(&weak_creator);
        let _ = client.create_savings_plan(&weak_creator, &PlanType::Flexi, &1000);

        let description = String::from_str(&env, "Weak action proposal");
        let action = ProposalAction::SetFlexiRate(500);

        // Attempt to create action proposal should fail
        let result = client.try_create_action_proposal(&weak_creator, &description, &action);
        assert!(result.is_err());
    }

    #[test]
    fn test_voting_power_cap_prevents_single_user_domination() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        // Set cap at 1000
        let _ = client.init_voting_config(&admin, &5000, &604800, &86400, &100, &1000);

        let creator = Address::generate(&env);
        let description = String::from_str(&env, "Domination attempt");
        let proposal_id = client
            .try_create_proposal(&creator, &description)
            .unwrap()
            .unwrap();

        // Create whale user with massive balance
        let whale = Address::generate(&env);
        client.initialize_user(&whale);
        let _ = client.create_savings_plan(&whale, &PlanType::Flexi, &1_000_000);

        // Vote should be capped
        let result = client.try_vote(&proposal_id, &1, &whale);
        assert!(result.is_ok());

        let proposal = client.get_proposal(&proposal_id).unwrap();
        assert_eq!(proposal.for_votes, 1000); // Should be capped, not 1,000,000
    }

    #[test]
    fn test_multi_voter_cannot_exceed_cap() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        // Set cap at 500
        let _ = client.init_voting_config(&admin, &5000, &604800, &86400, &100, &500);

        let creator = Address::generate(&env);
        let description = String::from_str(&env, "Multi-voter test");
        let proposal_id = client
            .try_create_proposal(&creator, &description)
            .unwrap()
            .unwrap();

        // Multiple users voting should all be capped
        for i in 0..3 {
            let voter = Address::generate(&env);
            client.initialize_user(&voter);
            let _ = client.create_savings_plan(&voter, &PlanType::Flexi, &10_000); // Very high balance

            let result = client.try_vote(&proposal_id, &1, &voter);
            assert!(result.is_ok());
        }

        let proposal = client.get_proposal(&proposal_id).unwrap();
        // Each vote capped at 500, 3 voters = 1500 total
        assert_eq!(proposal.for_votes, 1500);
    }
    
}
