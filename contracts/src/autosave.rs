use crate::errors::SavingsError;
use crate::flexi;
use crate::storage_types::{AutoSave, DataKey};
use crate::ttl;
use crate::users;
use soroban_sdk::{Address, Env, Vec};

/// Creates a new AutoSave schedule for recurring Flexi deposits
///
/// # Arguments
/// * `env` - The contract environment
/// * `user` - The user creating the schedule
/// * `amount` - The amount to deposit on each execution (must be > 0)
/// * `interval_seconds` - How often the schedule runs in seconds (must be > 0)
/// * `start_time` - Unix timestamp for the first execution
///
/// # Returns
/// * `Ok(u64)` - The unique schedule ID
/// * `Err(SavingsError)` - If validation fails
pub fn create_autosave(
    env: &Env,
    user: Address,
    amount: i128,
    interval_seconds: u64,
    start_time: u64,
) -> Result<u64, SavingsError> {
    user.require_auth();

    // Validate amount
    if amount <= 0 {
        return Err(SavingsError::InvalidAmount);
    }

    // Validate interval
    if interval_seconds == 0 {
        return Err(SavingsError::InvalidTimestamp);
    }

    // Ensure user exists
    if !users::user_exists(env, &user) {
        return Err(SavingsError::UserNotFound);
    }

    // Generate unique schedule ID
    let schedule_id = get_next_schedule_id(env);

    // Create the schedule
    let schedule = AutoSave {
        id: schedule_id,
        user: user.clone(),
        amount,
        interval_seconds,
        next_execution_time: start_time,
        is_active: true,
    };

    // Store the schedule
    env.storage()
        .persistent()
        .set(&DataKey::AutoSave(schedule_id), &schedule);

    // Link schedule to user
    add_schedule_to_user(env, &user, schedule_id);

    // Increment the next schedule ID
    increment_next_schedule_id(env);

    // Extend TTL for new schedule and user list
    ttl::extend_autosave_ttl(env, schedule_id);
    ttl::extend_user_plan_list_ttl(env, &DataKey::UserAutoSaves(user.clone()));

    Ok(schedule_id)
}

/// Executes an AutoSave schedule if it's due
///
/// # Arguments
/// * `env` - The contract environment
/// * `schedule_id` - The ID of the schedule to execute
///
/// # Returns
/// * `Ok(())` - If execution succeeds
/// * `Err(SavingsError)` - If the schedule is not found, inactive, or not yet due
pub fn execute_autosave(env: &Env, schedule_id: u64) -> Result<(), SavingsError> {
    // Fetch the schedule
    let mut schedule: AutoSave = env
        .storage()
        .persistent()
        .get(&DataKey::AutoSave(schedule_id))
        .ok_or(SavingsError::PlanNotFound)?;

    // Ensure schedule is active
    if !schedule.is_active {
        return Err(SavingsError::InvalidPlanConfig);
    }

    // Ensure current time >= next_execution_time
    let current_time = env.ledger().timestamp();
    if current_time < schedule.next_execution_time {
        return Err(SavingsError::InvalidTimestamp);
    }

    // Perform Flexi deposit
    flexi::flexi_deposit(env.clone(), schedule.user.clone(), schedule.amount)?;

    // Update next execution time
    schedule.next_execution_time += schedule.interval_seconds;

    // Save updated schedule
    env.storage()
        .persistent()
        .set(&DataKey::AutoSave(schedule_id), &schedule);

    // Extend TTL on execution (active schedule gets full extension)
    ttl::extend_autosave_ttl(env, schedule_id);

    Ok(())
}

/// Batch-executes multiple AutoSave schedules that are due.
///
/// This function is designed to be called by an external bot or relayer to
/// process multiple due schedules in a single contract invocation, improving
/// efficiency and reducing per-call overhead.
///
/// # Arguments
/// * `env` - The contract environment
/// * `schedule_ids` - A vector of schedule IDs to attempt execution on
///
/// # Returns
/// A `Vec<bool>` where each element corresponds to the schedule at the same
/// index in `schedule_ids`:
/// - `true`  — the schedule was due and executed successfully
/// - `false` — the schedule was skipped (not found, inactive, not yet due, or deposit failed)
///
/// # Guarantees
/// - One failed or skipped schedule does **not** revert the entire batch.
/// - Only schedules whose `next_execution_time <= current_ledger_timestamp` are executed.
/// - For each executed schedule, a Flexi deposit is performed and `next_execution_time` is
///   advanced by `interval_seconds`.
pub fn execute_due_autosaves(env: &Env, schedule_ids: Vec<u64>) -> Vec<bool> {
    let current_time = env.ledger().timestamp();
    let mut results = Vec::new(env);

    for i in 0..schedule_ids.len() {
        let schedule_id = schedule_ids.get(i).unwrap();

        // Attempt to fetch the schedule; skip if not found
        let maybe_schedule: Option<AutoSave> = env
            .storage()
            .persistent()
            .get(&DataKey::AutoSave(schedule_id));

        let schedule = match maybe_schedule {
            Some(s) => s,
            None => {
                results.push_back(false);
                continue;
            }
        };

        // Skip inactive schedules
        if !schedule.is_active {
            results.push_back(false);
            continue;
        }

        // Skip schedules that are not yet due
        if current_time < schedule.next_execution_time {
            results.push_back(false);
            continue;
        }

        // Attempt the Flexi deposit; if it fails, mark as false and continue
        let deposit_result =
            flexi::flexi_deposit(env.clone(), schedule.user.clone(), schedule.amount);

        if deposit_result.is_err() {
            results.push_back(false);
            continue;
        }

        // Update next execution time and persist
        let mut updated_schedule = schedule.clone();
        updated_schedule.next_execution_time += updated_schedule.interval_seconds;
        env.storage()
            .persistent()
            .set(&DataKey::AutoSave(schedule_id), &updated_schedule);

        results.push_back(true);
    }

    results
}

/// Cancels an AutoSave schedule
///
/// # Arguments
/// * `env` - The contract environment
/// * `user` - The user cancelling the schedule
/// * `schedule_id` - The ID of the schedule to cancel
///
/// # Returns
/// * `Ok(())` - If cancellation succeeds
/// * `Err(SavingsError)` - If the schedule is not found or user is not the owner
pub fn cancel_autosave(env: &Env, user: Address, schedule_id: u64) -> Result<(), SavingsError> {
    user.require_auth();

    // Fetch the schedule
    let mut schedule: AutoSave = env
        .storage()
        .persistent()
        .get(&DataKey::AutoSave(schedule_id))
        .ok_or(SavingsError::PlanNotFound)?;

    // Ensure caller owns the schedule
    if schedule.user != user {
        return Err(SavingsError::Unauthorized);
    }

    // Deactivate the schedule
    schedule.is_active = false;

    // Save updated schedule
    env.storage()
        .persistent()
        .set(&DataKey::AutoSave(schedule_id), &schedule);

    Ok(())
}

/// Gets an AutoSave schedule by ID
pub fn get_autosave(env: &Env, schedule_id: u64) -> Option<AutoSave> {
    let schedule = env
        .storage()
        .persistent()
        .get(&DataKey::AutoSave(schedule_id));

    if schedule.is_some() {
        // Extend TTL on read
        ttl::extend_autosave_ttl(env, schedule_id);
    }

    schedule
}

/// Gets all AutoSave schedule IDs for a user
pub fn get_user_autosaves(env: &Env, user: &Address) -> Vec<u64> {
    let list_key = DataKey::UserAutoSaves(user.clone());
    let schedules = env
        .storage()
        .persistent()
        .get(&list_key)
        .unwrap_or(Vec::new(env));

    // Extend TTL on list access
    if !schedules.is_empty() {
        ttl::extend_user_plan_list_ttl(env, &list_key);
    }

    schedules
}

// ========== Helper Functions ==========

fn get_next_schedule_id(env: &Env) -> u64 {
    let counter_key = DataKey::NextAutoSaveId;
    let id = env.storage().persistent().get(&counter_key).unwrap_or(1);

    // Extend TTL on counter access
    ttl::extend_counter_ttl(env, &counter_key);

    id
}

fn increment_next_schedule_id(env: &Env) {
    let current_id = get_next_schedule_id(env);
    let counter_key = DataKey::NextAutoSaveId;
    env.storage()
        .persistent()
        .set(&counter_key, &(current_id + 1));

    // Extend TTL on counter update
    ttl::extend_counter_ttl(env, &counter_key);
}

fn add_schedule_to_user(env: &Env, user: &Address, schedule_id: u64) {
    let key = DataKey::UserAutoSaves(user.clone());
    let mut schedules: Vec<u64> = env
        .storage()
        .persistent()
        .get(&key)
        .unwrap_or(Vec::new(env));

    schedules.push_back(schedule_id);
    env.storage().persistent().set(&key, &schedules);

    // Extend TTL on list update
    ttl::extend_user_plan_list_ttl(env, &key);
}
