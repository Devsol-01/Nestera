#[cfg(test)]
mod governance_tests {
    use soroban_sdk::testutils::Ledger;
    #[test]
    fn test_full_governance_lifecycle() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();
        client.init_voting_config(&admin, &5000, &10, &5, &100, &10_000);

        let creator = Address::generate(&env);
        let voter1 = Address::generate(&env);
        let voter2 = Address::generate(&env);
        client.initialize_user(&voter1);
        client.initialize_user(&voter2);
        client.create_savings_plan(&voter1, &PlanType::Flexi, &10000);
        client.create_savings_plan(&voter2, &PlanType::Flexi, &20000);

        let desc = String::from_str(&env, "Lifecycle proposal");
        let proposal_id = client.create_proposal(&creator, &desc);

        client.vote(&proposal_id, &1, &voter1); // For
        client.vote(&proposal_id, &1, &voter2); // For

        // Advance ledger time to after voting period
        env.ledger().with_mut(|li| li.timestamp += 11);
        client.queue_proposal(&proposal_id);
        env.ledger().with_mut(|li| li.timestamp += 6);
        client.execute_proposal(&proposal_id);
        let proposal = client.get_proposal(&proposal_id).unwrap();
        assert!(proposal.executed);
    }

    #[test]
    fn test_governance_attack_scenarios() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();
        client.init_voting_config(&admin, &5000, &10, &5, &100, &10_000);

        let creator = Address::generate(&env);
        let attacker = Address::generate(&env);
        client.initialize_user(&attacker);
        client.create_savings_plan(&attacker, &PlanType::Flexi, &50); // Not enough power

        let desc = String::from_str(&env, "Attack proposal");
        let proposal_id = client.create_proposal(&creator, &desc);

        // Attacker tries to vote multiple times
        client.vote(&proposal_id, &1, &attacker);
        let result = client.try_vote(&proposal_id, &1, &attacker);
        assert!(result.is_err()); // No double voting

        // Attacker tries to queue before voting period ends
        let early_queue = client.try_queue_proposal(&proposal_id);
        assert!(early_queue.is_err());

        // Attacker tries to execute before timelock
        env.ledger().with_mut(|li| li.timestamp += 11);
        client.queue_proposal(&proposal_id);
        let early_exec = client.try_execute_proposal(&proposal_id);
        assert!(early_exec.is_err());
    }

    use crate::governance_events::{ProposalCreated, VoteCast};
    use crate::rewards::storage_types::RewardsConfig;
    use crate::{NesteraContract, NesteraContractClient, PlanType};
    use soroban_sdk::symbol_short;
    use soroban_sdk::IntoVal;
    use soroban_sdk::{
        testutils::{Address as _, Events},
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

    // ────────────────────────────────────────────────────────────────────────────────
    // Existing tests (kept + fixed unwrap usage)
    // ────────────────────────────────────────────────────────────────────────────────

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
    fn test_init_voting_config() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        let result = client.try_init_voting_config(&admin, &5000, &604800, &86400, &100, &10_000);
        assert!(result.is_ok());

        let config = client.try_get_voting_config().unwrap().unwrap();
        assert_eq!(config.quorum, 5000);
        assert_eq!(config.voting_period, 604800);
        assert_eq!(config.timelock_duration, 86400);
    }

    #[test]
    fn test_create_proposal() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        client.init_voting_config(&admin, &5000, &604800, &86400, &100, &10_000);

        let creator = Address::generate(&env);
        let description = String::from_str(&env, "Test proposal");

        let proposal_id = client.create_proposal(&creator, &description);

        assert_eq!(proposal_id, 1);
    }

    #[test]
    fn test_get_proposal() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        client.init_voting_config(&admin, &5000, &604800, &86400, &100, &10_000);

        let creator = Address::generate(&env);
        let description = String::from_str(&env, "Test proposal");
        let proposal_id = client.create_proposal(&creator, &description);

        let proposal = client.get_proposal(&proposal_id).unwrap();
        let now = env.ledger().timestamp();

        assert_eq!(proposal.id, 1);
        assert_eq!(proposal.creator, creator);
        assert!(!proposal.executed);
        assert_eq!(proposal.for_votes, 0);
        assert_eq!(proposal.against_votes, 0);
        assert_eq!(proposal.start_time, now);
    }

    #[test]
    fn test_list_proposals() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        client.init_voting_config(&admin, &5000, &604800, &86400, &100, &10_000);

        let creator = Address::generate(&env);
        let desc1 = String::from_str(&env, "Proposal 1");
        let desc2 = String::from_str(&env, "Proposal 2");

        let _ = client.create_proposal(&creator, &desc1);
        let _ = client.create_proposal(&creator, &desc2);

        let proposals = client.list_proposals();
        assert_eq!(proposals.len(), 2);
        assert_eq!(proposals.get(0).unwrap(), 1);
        assert_eq!(proposals.get(1).unwrap(), 2);
    }

    #[test]
    fn test_proposal_stored_correctly() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        client.init_voting_config(&admin, &5000, &604800, &86400, &100, &10_000);

        let creator = Address::generate(&env);
        let description = String::from_str(&env, "Store test");
        let proposal_id = client.create_proposal(&creator, &description);

        let proposal = client.get_proposal(&proposal_id).unwrap();
        let now = env.ledger().timestamp();

        assert_eq!(proposal.description, description);
        assert_eq!(proposal.start_time, now);
        assert_eq!(proposal.end_time, now + 604800);
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // NEW TESTS: Governance Event Logging
    // ────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_proposal_created_emits_event() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        client.init_voting_config(&admin, &5000, &604800, &86400, &100, &10_000);

        let creator = Address::generate(&env);
        let description = String::from_str(&env, "Test proposal description");

        let proposal_id = client.create_proposal(&creator, &description);

        let events = env.events().all();

        let created_event_opt = events.iter().rev().find(|e| {
            e.0 == client.address
                && e.1
                    == (
                        symbol_short!("gov"),
                        symbol_short!("created"),
                        creator.clone(),
                    )
                        .into_val(&env)
        });

        assert!(
            created_event_opt.is_some(),
            "ProposalCreated event not emitted"
        );
        let event_data: ProposalCreated = created_event_opt.unwrap().2.clone().into_val(&env);

        assert_eq!(event_data.proposal_id, proposal_id);
        assert_eq!(event_data.creator, creator);
        assert_eq!(event_data.description, description);
    }

    #[test]
    fn test_vote_cast_emits_event() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        client.init_voting_config(&admin, &5000, &604800, &86400, &100, &10_000);

        let creator = Address::generate(&env);
        let voter = Address::generate(&env);

        client.initialize_user(&voter);
        client.create_savings_plan(&voter, &PlanType::Flexi, &10000);

        let proposal_id = client.create_proposal(&creator, &String::from_str(&env, "Vote test"));

        client.vote(&proposal_id, &1, &voter);

        let events = env.events().all();

        let vote_event_opt = events.iter().rev().find(|e| {
            e.0 == client.address
                && e.1
                    == (symbol_short!("gov"), symbol_short!("voted"), voter.clone()).into_val(&env)
        });

        assert!(vote_event_opt.is_some(), "VoteCast event not emitted");
        let event_data: VoteCast = vote_event_opt.unwrap().2.clone().into_val(&env);

        assert_eq!(event_data.proposal_id, proposal_id);
        assert_eq!(event_data.voter, voter);
        assert_eq!(event_data.vote_type, 1);
        assert!(event_data.weight > 0);
    }
}
