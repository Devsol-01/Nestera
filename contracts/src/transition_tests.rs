#[cfg(test)]
mod transition_tests {
    use crate::governance::ProposalAction;
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
        client.initialize_rewards_config(&config);

        (env, client, admin)
    }

    #[test]
    fn test_admin_can_set_rates_before_governance() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        let result = client.try_set_flexi_rate(&admin, &500);
        assert!(result.is_ok());
        assert_eq!(client.get_flexi_rate(), 500);
    }

    #[test]
    fn test_non_admin_cannot_set_rates_before_governance() {
        let (env, client, _) = setup_contract();
        let non_admin = Address::generate(&env);
        env.mock_all_auths();

        let result = client.try_set_flexi_rate(&non_admin, &500);
        assert!(result.is_err());
    }

    #[test]
    fn test_admin_can_pause_before_governance() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        let result = client.try_pause(&admin);
        assert!(result.is_ok());
        assert!(client.is_paused());
    }

    #[test]
    fn test_governance_activation() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        assert!(!client.is_governance_active());

        let result = client.try_activate_governance(&admin);
        assert!(result.is_ok());
        assert!(client.is_governance_active());
    }

    #[test]
    fn test_admin_can_still_act_after_governance_active() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        client.activate_governance(&admin);
        let result = client.try_set_flexi_rate(&admin, &600);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_action_proposal() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        client.init_voting_config(&admin, &5000, &604800, &86400, &100, &10_000);

        let creator = Address::generate(&env);
        let description = String::from_str(&env, "Set flexi rate to 500");

        client.initialize_user(&creator);
        let _ = client.create_savings_plan(&creator, &PlanType::Flexi, &1000);

        let action = ProposalAction::SetFlexiRate(500);

        let proposal_id = client
            .try_create_action_proposal(&creator, &description, &action)
            .unwrap()
            .unwrap();

        let proposal = client.get_action_proposal(&proposal_id).unwrap();
        assert_eq!(proposal.action, ProposalAction::SetFlexiRate(500));
    }

    #[test]
    fn test_backward_compatibility_existing_settings() {
        let (env, client, admin) = setup_contract();
        env.mock_all_auths();

        client.set_flexi_rate(&admin, &300);
        client.set_goal_rate(&admin, &400);

        assert_eq!(client.get_flexi_rate(), 300);
        assert_eq!(client.get_goal_rate(), 400);

        client.activate_governance(&admin);

        assert_eq!(client.get_flexi_rate(), 300);
        assert_eq!(client.get_goal_rate(), 400);
    }
}
