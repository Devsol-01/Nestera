use soroban_sdk::{Address, Env, Vec};

use crate::errors::SavingsError;
use crate::storage_types::{DataKey, GoalSave, User};
use crate::users;

pub fn create_goal_save(
    env: &Env,
    user: Address,
    goal_name: soroban_sdk::Symbol,
    target_amount: i128,
    initial_deposit: i128,
) -> Result<u64, SavingsError> {
    user.require_auth();

    if target_amount <= 0 {
        return Err(SavingsError::InvalidAmount);
    }

    if initial_deposit < 0 {
        return Err(SavingsError::InvalidAmount);
    }

    if !users::user_exists(env, &user) {
        return Err(SavingsError::UserNotFound);
    }

    let current_time = env.ledger().timestamp();
    let goal_id = get_next_goal_id(env);

    let goal_save = GoalSave {
        id: goal_id,
        owner: user.clone(),
        goal_name: goal_name.clone(),
        target_amount,
        current_amount: initial_deposit,
        interest_rate: 500,
        start_time: current_time,
        is_completed: initial_deposit >= target_amount,
        is_withdrawn: false,
    };

    env.storage()
        .persistent()
        .set(&DataKey::GoalSave(goal_id), &goal_save);

    add_goal_to_user(env, &user, goal_id);
    increment_next_goal_id(env);

    Ok(goal_id)
}

pub fn deposit_to_goal_save(
    env: &Env,
    user: Address,
    goal_id: u64,
    amount: i128,
) -> Result<(), SavingsError> {
    user.require_auth();

    if amount <= 0 {
        return Err(SavingsError::InvalidAmount);
    }

    let mut goal_save = get_goal_save(env, goal_id).ok_or(SavingsError::PlanNotFound)?;

    if goal_save.owner != user {
        return Err(SavingsError::Unauthorized);
    }

    if goal_save.is_completed {
        return Err(SavingsError::PlanCompleted);
    }

    goal_save.current_amount = goal_save
        .current_amount
        .checked_add(amount)
        .ok_or(SavingsError::Overflow)?;

    if goal_save.current_amount >= goal_save.target_amount {
        goal_save.is_completed = true;
    }

    env.storage()
        .persistent()
        .set(&DataKey::GoalSave(goal_id), &goal_save);

    Ok(())
}

pub fn withdraw_completed_goal_save(
    env: &Env,
    user: Address,
    goal_id: u64,
) -> Result<i128, SavingsError> {
    user.require_auth();

    if !users::user_exists(env, &user) {
        return Err(SavingsError::UserNotFound);
    }

    let mut goal_save = get_goal_save(env, goal_id).ok_or(SavingsError::PlanNotFound)?;

    if goal_save.owner != user {
        return Err(SavingsError::Unauthorized);
    }

    if !goal_save.is_completed {
        return Err(SavingsError::TooEarly);
    }

    if goal_save.is_withdrawn {
        return Err(SavingsError::PlanCompleted);
    }

    goal_save.is_withdrawn = true;

    env.storage()
        .persistent()
        .set(&DataKey::GoalSave(goal_id), &goal_save);

    let user_key = DataKey::User(user.clone());
    if let Some(mut user_data) = env.storage().persistent().get::<DataKey, User>(&user_key) {
        user_data.total_balance = user_data
            .total_balance
            .checked_add(goal_save.current_amount)
            .ok_or(SavingsError::Overflow)?;
        env.storage().persistent().set(&user_key, &user_data);
    }

    Ok(goal_save.current_amount)
}

pub fn break_goal_save(env: &Env, user: Address, goal_id: u64) -> Result<(), SavingsError> {
    user.require_auth();

    if !users::user_exists(env, &user) {
        return Err(SavingsError::UserNotFound);
    }

    let mut goal_save = get_goal_save(env, goal_id).ok_or(SavingsError::PlanNotFound)?;

    if goal_save.owner != user {
        return Err(SavingsError::Unauthorized);
    }

    if goal_save.is_completed {
        return Err(SavingsError::PlanCompleted);
    }

    if goal_save.is_withdrawn {
        return Err(SavingsError::PlanCompleted);
    }

    goal_save.is_withdrawn = true;

    env.storage()
        .persistent()
        .set(&DataKey::GoalSave(goal_id), &goal_save);

    let user_key = DataKey::User(user.clone());
    if let Some(mut user_data) = env.storage().persistent().get::<DataKey, User>(&user_key) {
        user_data.total_balance = user_data
            .total_balance
            .checked_add(goal_save.current_amount)
            .ok_or(SavingsError::Overflow)?;
        env.storage().persistent().set(&user_key, &user_data);
    }

    remove_goal_from_user(env, &user, goal_id);

    Ok(())
}

pub fn get_goal_save(env: &Env, goal_id: u64) -> Option<GoalSave> {
    env.storage().persistent().get(&DataKey::GoalSave(goal_id))
}

pub fn get_user_goal_saves(env: &Env, user: &Address) -> Vec<u64> {
    env.storage()
        .persistent()
        .get(&DataKey::UserGoalSaves(user.clone()))
        .unwrap_or_else(|| Vec::new(env))
}

fn get_next_goal_id(env: &Env) -> u64 {
    env.storage()
        .persistent()
        .get(&DataKey::NextGoalId)
        .unwrap_or(1u64)
}

fn increment_next_goal_id(env: &Env) {
    let current_id = get_next_goal_id(env);
    env.storage()
        .persistent()
        .set(&DataKey::NextGoalId, &(current_id + 1));
}

fn add_goal_to_user(env: &Env, user: &Address, goal_id: u64) {
    let mut user_goals = get_user_goal_saves(env, user);
    user_goals.push_back(goal_id);
    env.storage()
        .persistent()
        .set(&DataKey::UserGoalSaves(user.clone()), &user_goals);
}

fn remove_goal_from_user(env: &Env, user: &Address, goal_id: u64) {
    let user_goals = get_user_goal_saves(env, user);
    let mut new_goals = Vec::new(env);

    for i in 0..user_goals.len() {
        if let Some(id) = user_goals.get(i) {
            if id != goal_id {
                new_goals.push_back(id);
            }
        }
    }

    env.storage()
        .persistent()
        .set(&DataKey::UserGoalSaves(user.clone()), &new_goals);
}

#[cfg(test)]
mod tests {
    use crate::{NesteraContract, NesteraContractClient};
    use soroban_sdk::{testutils::Address as _, Address, Env, Symbol};

    fn setup_test_env() -> (Env, NesteraContractClient<'static>) {
        let env = Env::default();
        let contract_id = env.register(NesteraContract, ());
        let client = NesteraContractClient::new(&env, &contract_id);
        (env, client)
    }

    #[test]
    fn test_create_goal_save_success() {
        let (env, client) = setup_test_env();
        let user = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user);

        let goal_name = Symbol::new(&env, "vacation");
        let target = 10000i128;
        let initial = 1000i128;

        let goal_id = client.create_goal_save(&user, &goal_name, &target, &initial);
        assert_eq!(goal_id, 1);

        let goal_save = client.get_goal_save_detail(&goal_id);
        assert_eq!(goal_save.owner, user);
        assert_eq!(goal_save.target_amount, target);
        assert_eq!(goal_save.current_amount, initial);
        assert!(!goal_save.is_completed);
        assert!(!goal_save.is_withdrawn);
    }

    #[test]
    fn test_deposit_to_goal_save() {
        let (env, client) = setup_test_env();
        let user = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user);

        let goal_name = Symbol::new(&env, "house");
        let target = 5000i128;
        let initial = 1000i128;

        let goal_id = client.create_goal_save(&user, &goal_name, &target, &initial);
        client.deposit_to_goal_save(&user, &goal_id, &2000);

        let goal_save = client.get_goal_save_detail(&goal_id);
        assert_eq!(goal_save.current_amount, 3000);
        assert!(!goal_save.is_completed);
    }

    #[test]
    fn test_goal_completion_on_deposit() {
        let (env, client) = setup_test_env();
        let user = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user);

        let goal_name = Symbol::new(&env, "laptop");
        let target = 5000i128;
        let initial = 3000i128;

        let goal_id = client.create_goal_save(&user, &goal_name, &target, &initial);
        client.deposit_to_goal_save(&user, &goal_id, &2000);

        let goal_save = client.get_goal_save_detail(&goal_id);
        assert_eq!(goal_save.current_amount, 5000);
        assert!(goal_save.is_completed);
    }

    #[test]
    fn test_withdraw_completed_goal_save_success() {
        let (env, client) = setup_test_env();
        let user = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user);

        let goal_name = Symbol::new(&env, "car");
        let target = 1000i128;
        let initial = 1000i128;

        let goal_id = client.create_goal_save(&user, &goal_name, &target, &initial);

        let goal_save = client.get_goal_save_detail(&goal_id);
        assert!(goal_save.is_completed);

        let amount = client.withdraw_completed_goal_save(&user, &goal_id);
        assert_eq!(amount, 1000);

        let goal_save_after = client.get_goal_save_detail(&goal_id);
        assert!(goal_save_after.is_withdrawn);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #51)")]
    fn test_withdraw_incomplete_goal_fails() {
        let (env, client) = setup_test_env();
        let user = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user);

        let goal_name = Symbol::new(&env, "bike");
        let target = 5000i128;
        let initial = 1000i128;

        let goal_id = client.create_goal_save(&user, &goal_name, &target, &initial);

        client.withdraw_completed_goal_save(&user, &goal_id);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #23)")]
    fn test_withdraw_already_withdrawn_fails() {
        let (env, client) = setup_test_env();
        let user = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user);

        let goal_name = Symbol::new(&env, "fund");
        let target = 1000i128;
        let initial = 1000i128;

        let goal_id = client.create_goal_save(&user, &goal_name, &target, &initial);
        client.withdraw_completed_goal_save(&user, &goal_id);
        client.withdraw_completed_goal_save(&user, &goal_id);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1)")]
    fn test_withdraw_unauthorized_fails() {
        let (env, client) = setup_test_env();
        let user1 = Address::generate(&env);
        let user2 = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user1);
        client.initialize_user(&user2);

        let goal_name = Symbol::new(&env, "test");
        let target = 1000i128;
        let initial = 1000i128;

        let goal_id = client.create_goal_save(&user1, &goal_name, &target, &initial);
        client.withdraw_completed_goal_save(&user2, &goal_id);
    }

    #[test]
    fn test_break_goal_save_success() {
        let (env, client) = setup_test_env();
        let user = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user);

        let goal_name = Symbol::new(&env, "emergency");
        let target = 5000i128;
        let initial = 2000i128;

        let goal_id = client.create_goal_save(&user, &goal_name, &target, &initial);
        client.break_goal_save(&user, &goal_id);

        let goal_save = client.get_goal_save_detail(&goal_id);
        assert!(goal_save.is_withdrawn);

        let user_goals = client.get_user_goal_saves(&user);
        assert_eq!(user_goals.len(), 0);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #23)")]
    fn test_break_completed_goal_fails() {
        let (env, client) = setup_test_env();
        let user = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user);

        let goal_name = Symbol::new(&env, "done");
        let target = 1000i128;
        let initial = 1000i128;

        let goal_id = client.create_goal_save(&user, &goal_name, &target, &initial);
        client.break_goal_save(&user, &goal_id);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1)")]
    fn test_break_unauthorized_fails() {
        let (env, client) = setup_test_env();
        let user1 = Address::generate(&env);
        let user2 = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user1);
        client.initialize_user(&user2);

        let goal_name = Symbol::new(&env, "other");
        let target = 5000i128;
        let initial = 2000i128;

        let goal_id = client.create_goal_save(&user1, &goal_name, &target, &initial);
        client.break_goal_save(&user2, &goal_id);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #41)")]
    fn test_create_goal_save_invalid_target_amount() {
        let (env, client) = setup_test_env();
        let user = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user);

        let goal_name = Symbol::new(&env, "invalid");
        let target = 0i128;
        let initial = 100i128;

        client.create_goal_save(&user, &goal_name, &target, &initial);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #10)")]
    fn test_create_goal_save_user_not_found() {
        let (env, client) = setup_test_env();
        let user = Address::generate(&env);

        env.mock_all_auths();

        let goal_name = Symbol::new(&env, "nouser");
        let target = 5000i128;
        let initial = 1000i128;

        client.create_goal_save(&user, &goal_name, &target, &initial);
    }
}
