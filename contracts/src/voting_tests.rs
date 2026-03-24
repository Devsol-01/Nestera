#[cfg(test)]
mod voting_tests {

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

    fn setup_with_proposal() -> (Env, NesteraContractClient<'static>, Address, Address, u64) {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        client.init_voting_config(&admin, &5000, &604800, &86400, &100, &10_000);

        let creator = Address::generate(&env);
        let description = String::from_str(&env, "Test proposal");
        let proposal_id = client
            .try_create_proposal(&creator, &description)
            .unwrap()
            .unwrap();

        (env, client, admin, creator, proposal_id)
    }

    #[test]
    fn test_vote_for() {
        let (env, client, _admin, _creator, proposal_id) = setup_with_proposal();
        let voter = Address::generate(&env);
        env.mock_all_auths();

        client.initialize_user(&voter);
        let _ = client.create_savings_plan(&voter, &PlanType::Flexi, &1000);

        let result = client.try_vote(&proposal_id, &1, &voter);
        assert!(result.is_ok());

        let proposal = client.get_proposal(&proposal_id).unwrap();
        assert_eq!(proposal.for_votes, 1000);
        assert_eq!(proposal.against_votes, 0);
        assert_eq!(proposal.abstain_votes, 0);
    }

    #[test]
    fn test_vote_against() {
        let (env, client, _admin, _creator, proposal_id) = setup_with_proposal();
        let voter = Address::generate(&env);
        env.mock_all_auths();

        client.initialize_user(&voter);
        let _ = client.create_savings_plan(&voter, &PlanType::Flexi, &2000);

        let result = client.try_vote(&proposal_id, &2, &voter);
        assert!(result.is_ok());

        let proposal = client.get_proposal(&proposal_id).unwrap();
        assert_eq!(proposal.for_votes, 0);
        assert_eq!(proposal.against_votes, 2000);
        assert_eq!(proposal.abstain_votes, 0);
    }

    #[test]
    fn test_vote_abstain() {
        let (env, client, _admin, _creator, proposal_id) = setup_with_proposal();
        let voter = Address::generate(&env);
        env.mock_all_auths();

        client.initialize_user(&voter);
        let _ = client.create_savings_plan(&voter, &PlanType::Flexi, &1500);

        let result = client.try_vote(&proposal_id, &3, &voter);
        assert!(result.is_ok());

        let proposal = client.get_proposal(&proposal_id).unwrap();
        assert_eq!(proposal.for_votes, 0);
        assert_eq!(proposal.against_votes, 0);
        assert_eq!(proposal.abstain_votes, 1500);
    }

    #[test]
    fn test_multiple_voters() {
        let (env, client, _admin, _creator, proposal_id) = setup_with_proposal();
        env.mock_all_auths();

        let voter1 = Address::generate(&env);
        let voter2 = Address::generate(&env);
        let voter3 = Address::generate(&env);

        client.initialize_user(&voter1);
        client.initialize_user(&voter2);
        client.initialize_user(&voter3);

        let _ = client.create_savings_plan(&voter1, &PlanType::Flexi, &1000);
        let _ = client.create_savings_plan(&voter2, &PlanType::Flexi, &2000);
        let _ = client.create_savings_plan(&voter3, &PlanType::Flexi, &1500);

        client.vote(&proposal_id, &1, &voter1);
        client.vote(&proposal_id, &1, &voter2);
        client.vote(&proposal_id, &2, &voter3);

        let proposal = client.get_proposal(&proposal_id).unwrap();
        assert_eq!(proposal.for_votes, 3000);
        assert_eq!(proposal.against_votes, 1500);
        assert_eq!(proposal.abstain_votes, 0);
    }

    #[test]
    fn test_no_double_voting() {
        let (env, client, _admin, _creator, proposal_id) = setup_with_proposal();
        let voter = Address::generate(&env);
        env.mock_all_auths();

        client.initialize_user(&voter);
        let _ = client.create_savings_plan(&voter, &PlanType::Flexi, &1000);

        client.vote(&proposal_id, &1, &voter);

        let result = client.try_vote(&proposal_id, &2, &voter);
        assert!(result.is_err());

        let proposal = client.get_proposal(&proposal_id).unwrap();
        assert_eq!(proposal.for_votes, 1000);
        assert_eq!(proposal.against_votes, 0);
    }

    #[test]
    fn test_has_voted() {
        let (env, client, _admin, _creator, proposal_id) = setup_with_proposal();
        let voter = Address::generate(&env);
        env.mock_all_auths();

        client.initialize_user(&voter);
        let _ = client.create_savings_plan(&voter, &PlanType::Flexi, &1000);

        assert!(!client.has_voted(&proposal_id, &voter));

        client.vote(&proposal_id, &1, &voter);

        assert!(client.has_voted(&proposal_id, &voter));
    }

    #[test]
    fn test_vote_requires_voting_power() {
        let (env, client, _admin, _creator, proposal_id) = setup_with_proposal();
        let voter = Address::generate(&env);
        env.mock_all_auths();

        client.initialize_user(&voter);

        let result = client.try_vote(&proposal_id, &1, &voter);
        assert!(result.is_err());
    }

    #[test]
    fn test_vote_invalid_type() {
        let (env, client, _admin, _creator, proposal_id) = setup_with_proposal();
        let voter = Address::generate(&env);
        env.mock_all_auths();

        client.initialize_user(&voter);
        let _ = client.create_savings_plan(&voter, &PlanType::Flexi, &1000);

        let result = client.try_vote(&proposal_id, &0, &voter);
        assert!(result.is_err());

        let result = client.try_vote(&proposal_id, &4, &voter);
        assert!(result.is_err());
    }

    #[test]
    fn test_vote_outside_period() {
        let (env, client, _admin, _creator, proposal_id) = setup_with_proposal();
        let voter = Address::generate(&env);
        env.mock_all_auths();

        client.initialize_user(&voter);
        let _ = client.create_savings_plan(&voter, &PlanType::Flexi, &1000);

        env.ledger().with_mut(|li| {
            li.timestamp += 604800 + 1;
        });

        let result = client.try_vote(&proposal_id, &1, &voter);
        assert!(result.is_err());
    }

    #[test]
    fn test_vote_on_nonexistent_proposal() {
        let (env, client, _admin) = setup_contract();
        let voter = Address::generate(&env);
        env.mock_all_auths();

        client.initialize_user(&voter);
        let _ = client.create_savings_plan(&voter, &PlanType::Flexi, &1000);

        let result = client.try_vote(&999, &1, &voter);
        assert!(result.is_err());
    }

    #[test]
    fn test_vote_counted_correctly() {
        let (env, client, _admin, _creator, proposal_id) = setup_with_proposal();
        env.mock_all_auths();

        let voter1 = Address::generate(&env);
        let voter2 = Address::generate(&env);

        client.initialize_user(&voter1);
        client.initialize_user(&voter2);

        let _ = client.create_savings_plan(&voter1, &PlanType::Flexi, &5000);
        let _ = client.create_savings_plan(&voter2, &PlanType::Flexi, &3000);

        client.vote(&proposal_id, &1, &voter1);
        client.vote(&proposal_id, &1, &voter2);

        let proposal = client.get_proposal(&proposal_id).unwrap();
        assert_eq!(proposal.for_votes, 8000);
    }
}
