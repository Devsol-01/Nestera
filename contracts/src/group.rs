use crate::errors::SavingsError;
use crate::storage_types::{DataKey, GroupSave};
use soroban_sdk::{Address, Env, Vec};

/// Creates a new group savings plan.
///
/// The creator is automatically added as the first member (member_count = 1).
/// The group is assigned a unique auto-incrementing ID.
///
/// # Arguments
/// * `env` - The contract environment
/// * `creator` - The address of the user creating the group
/// * `title` - Title/name of the group savings plan
/// * `description` - Description of the group savings goal
/// * `category` - Category of the group savings (e.g., "education", "emergency")
/// * `target_amount` - Target amount to save (must be > 0)
/// * `contribution_type` - Type of contribution (0 = fixed, 1 = flexible, etc.)
/// * `contribution_amount` - Contribution amount or minimum (must be > 0)
/// * `is_public` - Whether the group is public or private
/// * `start_time` - Unix timestamp when the group starts
/// * `end_time` - Unix timestamp when the group ends (must be > start_time)
///
/// # Returns
/// `Ok(u64)` - The unique ID of the created group
/// `Err(SavingsError)` - If validation fails
///
/// # Errors
/// * `InvalidAmount` - If target_amount or contribution_amount <= 0
/// * `InvalidTimestamp` - If start_time >= end_time
/// * `InvalidGroupConfig` - If other parameters are invalid
pub fn create_group_save(
    env: &Env,
    creator: Address,
    title: String,
    description: String,
    category: String,
    target_amount: i128,
    contribution_type: u8,
    contribution_amount: i128,
    is_public: bool,
    start_time: u64,
    end_time: u64,
) -> Result<u64, SavingsError> {
    // Validate target_amount > 0
    if target_amount <= 0 {
        return Err(SavingsError::InvalidAmount);
    }

    // Validate contribution_amount > 0
    if contribution_amount <= 0 {
        return Err(SavingsError::InvalidAmount);
    }

    // Validate timestamps: start_time must be < end_time
    if start_time >= end_time {
        return Err(SavingsError::InvalidTimestamp);
    }

    // Validate contribution_type is reasonable (0-2 for fixed/flexible/percentage)
    if contribution_type > 2 {
        return Err(SavingsError::InvalidGroupConfig);
    }

    // Validate title and description are not empty
    if title.is_empty() || description.is_empty() {
        return Err(SavingsError::InvalidGroupConfig);
    }

    // Validate category is not empty
    if category.is_empty() {
        return Err(SavingsError::InvalidGroupConfig);
    }

    // Get the next group ID
    let next_id_key = DataKey::NextGroupId;
    let group_id: u64 = env
        .storage()
        .persistent()
        .get(&next_id_key)
        .unwrap_or(1u64);

    // Create the GroupSave struct with initial values
    let new_group = GroupSave {
        id: group_id,
        creator: creator.clone(),
        title,
        description,
        category,
        target_amount,
        current_amount: 0,
        contribution_type,
        contribution_amount,
        is_public,
        member_count: 1, // Creator is the first member
        start_time,
        end_time,
        is_completed: false,
    };

    // Store the GroupSave in persistent storage
    let group_key = DataKey::GroupSave(group_id);
    env.storage().persistent().set(&group_key, &new_group);

    // Update NextGroupId for the next group creation
    env.storage()
        .persistent()
        .set(&next_id_key, &(group_id + 1u64));

    // Add group_id to the creator's UserGroupSaves list
    add_group_to_user_list(env, &creator, group_id)?;

    // Emit event for group creation
    env.events().publish(
        (soroban_sdk::symbol_short!("create_group"), creator),
        group_id,
    );

    Ok(group_id)
}

/// Retrieves a group savings plan by ID.
///
/// # Arguments
/// * `env` - The contract environment
/// * `group_id` - The unique ID of the group
///
/// # Returns
/// `Some(GroupSave)` if the group exists, `None` otherwise
pub fn get_group_save(env: &Env, group_id: u64) -> Option<GroupSave> {
    let key = DataKey::GroupSave(group_id);
    env.storage().persistent().get(&key)
}

/// Checks if a group exists.
///
/// # Arguments
/// * `env` - The contract environment
/// * `group_id` - The unique ID of the group
///
/// # Returns
/// `true` if the group exists, `false` otherwise
pub fn group_exists(env: &Env, group_id: u64) -> bool {
    let key = DataKey::GroupSave(group_id);
    env.storage().persistent().has(&key)
}

/// Gets all group IDs that a user participates in.
///
/// # Arguments
/// * `env` - The contract environment
/// * `user` - The user address
///
/// # Returns
/// A vector of group IDs the user is involved in
pub fn get_user_groups(env: &Env, user: &Address) -> Vec<u64> {
    let key = DataKey::UserGroupSaves(user.clone());
    env.storage()
        .persistent()
        .get(&key)
        .unwrap_or(Vec::new(env))
}

/// Helper function to add a group ID to a user's list of groups.
///
/// # Arguments
/// * `env` - The contract environment
/// * `user` - The user address
/// * `group_id` - The group ID to add
///
/// # Returns
/// `Ok(())` on success
fn add_group_to_user_list(env: &Env, user: &Address, group_id: u64) -> Result<(), SavingsError> {
    let key = DataKey::UserGroupSaves(user.clone());
    let mut groups = env
        .storage()
        .persistent()
        .get(&key)
        .unwrap_or(Vec::new(env));

    groups.push_back(group_id);
    env.storage().persistent().set(&key, &groups);

    Ok(())
}
