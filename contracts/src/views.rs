use crate::errors::SavingsError;
use crate::storage_types::{
    DataKey, GoalSaveView, GroupSaveView, LockSaveView, PlanType, SavingsPlan, User,
};
use soroban_sdk::{Address, Env, Vec};

// ===========================================================================
// Helper Functions to Convert SavingsPlan to Specific Types
// ===========================================================================

fn to_lock_save(plan: &SavingsPlan) -> Option<LockSaveView> {
    match plan.plan_type {
        PlanType::Lock(locked_until) => Some(LockSaveView {
            plan_id: plan.plan_id,
            balance: plan.balance,
            start_time: plan.start_time,
            locked_until,
            interest_rate: plan.interest_rate,
            is_withdrawn: plan.is_withdrawn,
        }),
        _ => None,
    }
}

fn to_goal_save(plan: &SavingsPlan) -> Option<GoalSaveView> {
    match &plan.plan_type {
        PlanType::Goal(goal_name, target_amount, contribution_type) => Some(GoalSaveView {
            plan_id: plan.plan_id,
            balance: plan.balance,
            target_amount: *target_amount,
            start_time: plan.start_time,
            interest_rate: plan.interest_rate,
            is_completed: plan.is_completed,
            contribution_type: *contribution_type,
            goal_name: goal_name.clone(),
        }),
        _ => None,
    }
}

fn to_group_save(plan: &SavingsPlan) -> Option<GroupSaveView> {
    match plan.plan_type {
        PlanType::Group(group_id, is_public, contribution_type, target_amount) => {
            Some(GroupSaveView {
                plan_id: plan.plan_id,
                balance: plan.balance,
                target_amount,
                start_time: plan.start_time,
                interest_rate: plan.interest_rate,
                is_completed: plan.is_completed,
                is_public,
                contribution_type,
                group_id,
            })
        }
        _ => None,
    }
}

// ===========================================================================
// Lock Save Views
// ===========================================================================

pub fn get_user_ongoing_lock_saves(
    env: &Env,
    user: Address,
) -> Result<Vec<LockSaveView>, SavingsError> {
    if !crate::users::user_exists(env, &user) {
        return Err(SavingsError::UserNotFound);
    }

    let user_data: User = crate::users::get_user(env, &user)?;
    let mut ongoing_plans = Vec::new(env);

    for i in 1..=user_data.savings_count {
        let plan_id = i as u64;
        let key = DataKey::SavingsPlan(user.clone(), plan_id);

        if let Some(plan) = env.storage().persistent().get::<DataKey, SavingsPlan>(&key) {
            if let Some(lock_save) = to_lock_save(&plan) {
                // Ongoing means not withdrawn (and potentially check if locked_until > now,
                // but "ongoing" usually implies active/fresh. Let's assume active = not withdrawn)
                if !lock_save.is_withdrawn {
                    ongoing_plans.push_back(lock_save);
                }
            }
        }
    }
    Ok(ongoing_plans)
}

pub fn get_user_matured_lock_saves(
    env: &Env,
    user: Address,
) -> Result<Vec<LockSaveView>, SavingsError> {
    if !crate::users::user_exists(env, &user) {
        return Err(SavingsError::UserNotFound);
    }

    let user_data: User = crate::users::get_user(env, &user)?;
    let mut matured_plans = Vec::new(env);
    let current_time = env.ledger().timestamp();

    for i in 1..=user_data.savings_count {
        let plan_id = i as u64;
        let key = DataKey::SavingsPlan(user.clone(), plan_id);

        if let Some(plan) = env.storage().persistent().get::<DataKey, SavingsPlan>(&key) {
            if let Some(lock_save) = to_lock_save(&plan) {
                // Matured means lock time has passed
                if current_time >= lock_save.locked_until && !lock_save.is_withdrawn {
                    matured_plans.push_back(lock_save);
                }
            }
        }
    }
    Ok(matured_plans)
}

pub fn get_lock_save(env: &Env, user: Address, lock_id: u64) -> Result<LockSaveView, SavingsError> {
    let key = DataKey::SavingsPlan(user, lock_id);
    let plan = env
        .storage()
        .persistent()
        .get::<DataKey, SavingsPlan>(&key)
        .ok_or(SavingsError::PlanNotFound)?;

    to_lock_save(&plan).ok_or(SavingsError::PlanNotFound) // Or some mismatched type error? PlanNotFound seems safe enough
}

// ===========================================================================
// Goal Save Views
// ===========================================================================

pub fn get_user_live_goal_saves(
    env: &Env,
    user: Address,
) -> Result<Vec<GoalSaveView>, SavingsError> {
    if !crate::users::user_exists(env, &user) {
        return Err(SavingsError::UserNotFound);
    }

    let user_data: User = crate::users::get_user(env, &user)?;
    let mut live_plans = Vec::new(env);

    for i in 1..=user_data.savings_count {
        let plan_id = i as u64;
        let key = DataKey::SavingsPlan(user.clone(), plan_id);

        if let Some(plan) = env.storage().persistent().get::<DataKey, SavingsPlan>(&key) {
            if let Some(goal_save) = to_goal_save(&plan) {
                if !goal_save.is_completed {
                    live_plans.push_back(goal_save);
                }
            }
        }
    }
    Ok(live_plans)
}

pub fn get_user_completed_goal_saves(
    env: &Env,
    user: Address,
) -> Result<Vec<GoalSaveView>, SavingsError> {
    if !crate::users::user_exists(env, &user) {
        return Err(SavingsError::UserNotFound);
    }

    let user_data: User = crate::users::get_user(env, &user)?;
    let mut completed_plans = Vec::new(env);

    for i in 1..=user_data.savings_count {
        let plan_id = i as u64;
        let key = DataKey::SavingsPlan(user.clone(), plan_id);

        if let Some(plan) = env.storage().persistent().get::<DataKey, SavingsPlan>(&key) {
            if let Some(goal_save) = to_goal_save(&plan) {
                if goal_save.is_completed {
                    completed_plans.push_back(goal_save);
                }
            }
        }
    }
    Ok(completed_plans)
}

pub fn get_goal_save(env: &Env, user: Address, goal_id: u64) -> Result<GoalSaveView, SavingsError> {
    let key = DataKey::SavingsPlan(user, goal_id);
    let plan = env
        .storage()
        .persistent()
        .get::<DataKey, SavingsPlan>(&key)
        .ok_or(SavingsError::PlanNotFound)?;

    to_goal_save(&plan).ok_or(SavingsError::PlanNotFound)
}

// ===========================================================================
// Group Save Views
// ===========================================================================

pub fn get_user_live_group_saves(
    env: &Env,
    user: Address,
) -> Result<Vec<GroupSaveView>, SavingsError> {
    if !crate::users::user_exists(env, &user) {
        return Err(SavingsError::UserNotFound);
    }

    let user_data: User = crate::users::get_user(env, &user)?;
    let mut live_plans = Vec::new(env);

    for i in 1..=user_data.savings_count {
        let plan_id = i as u64;
        let key = DataKey::SavingsPlan(user.clone(), plan_id);

        if let Some(plan) = env.storage().persistent().get::<DataKey, SavingsPlan>(&key) {
            if let Some(group_save) = to_group_save(&plan) {
                if !group_save.is_completed {
                    live_plans.push_back(group_save);
                }
            }
        }
    }
    Ok(live_plans)
}

pub fn get_user_completed_group_saves(
    env: &Env,
    user: Address,
) -> Result<Vec<GroupSaveView>, SavingsError> {
    if !crate::users::user_exists(env, &user) {
        return Err(SavingsError::UserNotFound);
    }

    let user_data: User = crate::users::get_user(env, &user)?;
    let mut completed_plans = Vec::new(env);

    for i in 1..=user_data.savings_count {
        let plan_id = i as u64;
        let key = DataKey::SavingsPlan(user.clone(), plan_id);

        if let Some(plan) = env.storage().persistent().get::<DataKey, SavingsPlan>(&key) {
            if let Some(group_save) = to_group_save(&plan) {
                if group_save.is_completed {
                    completed_plans.push_back(group_save);
                }
            }
        }
    }
    Ok(completed_plans)
}

pub fn get_group_save(
    env: &Env,
    user: Address,
    group_id: u64,
) -> Result<GroupSaveView, SavingsError> {
    let key = DataKey::SavingsPlan(user, group_id);
    let plan = env
        .storage()
        .persistent()
        .get::<DataKey, SavingsPlan>(&key)
        .ok_or(SavingsError::PlanNotFound)?;

    to_group_save(&plan).ok_or(SavingsError::PlanNotFound)
}

// ===========================================================================
// Member Views
// ===========================================================================

pub fn is_group_member(env: &Env, group_id: u64, user: Address) -> Result<bool, SavingsError> {
    if !crate::users::user_exists(env, &user) {
        return Ok(false);
    }

    let user_data: User = crate::users::get_user(env, &user)?;

    for i in 1..=user_data.savings_count {
        let plan_id = i as u64;
        let key = DataKey::SavingsPlan(user.clone(), plan_id);

        if let Some(plan) = env.storage().persistent().get::<DataKey, SavingsPlan>(&key) {
            if let PlanType::Group(valid_group_id, _, _, _) = plan.plan_type {
                if valid_group_id == group_id {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

pub fn get_group_member_contribution(
    env: &Env,
    group_id: u64,
    user: Address,
) -> Result<i128, SavingsError> {
    if !crate::users::user_exists(env, &user) {
        return Err(SavingsError::UserNotFound);
    }

    let user_data: User = crate::users::get_user(env, &user)?;

    for i in 1..=user_data.savings_count {
        let plan_id = i as u64;
        let key = DataKey::SavingsPlan(user.clone(), plan_id);

        if let Some(plan) = env.storage().persistent().get::<DataKey, SavingsPlan>(&key) {
            if let PlanType::Group(valid_group_id, _, _, _) = plan.plan_type {
                if valid_group_id == group_id {
                    return Ok(plan.balance);
                }
            }
        }
    }

    Err(SavingsError::PlanNotFound)
}
