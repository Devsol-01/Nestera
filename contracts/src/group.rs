use crate::ensure_not_paused;
use crate::errors::SavingsError;
use crate::storage_types::{DataKey, GroupSave};
use crate::ttl;
use crate::users;
use soroban_sdk::{Address, Env, String, Vec};

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
    contribution_type: u32,
    contribution_amount: i128,
    is_public: bool,
    start_time: u64,
    end_time: u64,
) -> Result<u64, SavingsError> {
    ensure_not_paused(env)?;
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
    let group_id: u64 = env.storage().persistent().get(&next_id_key).unwrap_or(1u64);

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

    // Initialize the members list with the creator
    let members_key = DataKey::GroupMembers(group_id);
    let mut members = Vec::new(env);
    members.push_back(creator.clone());
    env.storage().persistent().set(&members_key, &members);

    // Initialize creator's contribution to 0
    let contribution_key = DataKey::GroupMemberContribution(group_id, creator.clone());
    env.storage().persistent().set(&contribution_key, &0i128);

    // Add group_id to the creator's UserGroupSaves list
    add_group_to_user_list(env, &creator, group_id)?;

    // Create a SavingsPlan for the creator so they can retrieve it via get_group_save
    let now = env.ledger().timestamp();
    let savings_plan = crate::storage_types::SavingsPlan {
        plan_id: group_id,
        plan_type: crate::storage_types::PlanType::Group(
            group_id,
            is_public,
            contribution_type,
            target_amount,
        ),
        balance: 0,
        start_time: now,
        last_deposit: 0,
        last_withdraw: 0,
        interest_rate: 500, // Default 5%
        is_completed: false,
        is_withdrawn: false,
    };

    let plan_key = DataKey::SavingsPlan(creator.clone(), group_id);
    env.storage().persistent().set(&plan_key, &savings_plan);

    // Extend TTL for new group, members list, and user data
    ttl::extend_group_ttl(env, group_id);
    ttl::extend_user_plan_list_ttl(env, &DataKey::UserGroupSaves(creator.clone()));
    ttl::extend_counter_ttl(env, &next_id_key);
    ttl::extend_plan_ttl(env, &plan_key);

    // Emit event for group creation
    env.events()
        .publish((soroban_sdk::symbol_short!("grp_new"), creator), group_id);

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
    let group = env.storage().persistent().get(&key);
    if group.is_some() {
        // Extend TTL on read
        ttl::extend_group_ttl(env, group_id);
    }
    group
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
    let exists = env.storage().persistent().has(&key);
    if exists {
        // Extend TTL on check
        ttl::extend_group_ttl(env, group_id);
    }
    exists
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
    let groups = env
        .storage()
        .persistent()
        .get(&key)
        .unwrap_or(Vec::new(env));

    // Extend TTL on list access
    if !groups.is_empty() {
        ttl::extend_user_plan_list_ttl(env, &key);
    }

    groups
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

    // Extend TTL on list update
    ttl::extend_user_plan_list_ttl(env, &key);

    Ok(())
}

/// Allows a user to join a public group savings plan.
///
/// # Arguments
/// * `env` - The contract environment
/// * `user` - The address of the user joining the group
/// * `group_id` - The ID of the group to join
///
/// # Returns
/// `Ok(())` on success
/// `Err(SavingsError)` if:
/// - User doesn't exist
/// - Group doesn't exist
/// - Group is not public
/// - User is already a member
pub fn join_group_save(env: &Env, user: Address, group_id: u64) -> Result<(), SavingsError> {
    ensure_not_paused(env)?;
    // Ensure user exists
    if !users::user_exists(env, &user) {
        return Err(SavingsError::UserNotFound);
    }

    // Fetch the group
    let group_key = DataKey::GroupSave(group_id);
    let mut group: GroupSave = env
        .storage()
        .persistent()
        .get(&group_key)
        .ok_or(SavingsError::PlanNotFound)?;

    // Validate that the group is public
    if !group.is_public {
        return Err(SavingsError::InvalidGroupConfig);
    }

    // Check if user is already a member
    let members_key = DataKey::GroupMembers(group_id);
    let mut members: Vec<Address> = env
        .storage()
        .persistent()
        .get(&members_key)
        .unwrap_or(Vec::new(env));

    // Check if user is already a member
    for i in 0..members.len() {
        if let Some(member) = members.get(i) {
            if member == user {
                return Err(SavingsError::InvalidGroupConfig);
            }
        }
    }

    // Add user to members list
    members.push_back(user.clone());
    env.storage().persistent().set(&members_key, &members);

    // Increment member count
    group.member_count += 1;
    env.storage().persistent().set(&group_key, &group);

    // Add group to user's list of groups
    add_group_to_user_list(env, &user, group_id)?;

    // Initialize user's contribution to 0
    let contribution_key = DataKey::GroupMemberContribution(group_id, user.clone());
    env.storage().persistent().set(&contribution_key, &0i128);

    // Create a SavingsPlan for the joining user
    let now = env.ledger().timestamp();
    let savings_plan = crate::storage_types::SavingsPlan {
        plan_id: group_id,
        plan_type: crate::storage_types::PlanType::Group(
            group_id,
            group.is_public,
            group.contribution_type,
            group.target_amount,
        ),
        balance: 0,
        start_time: now,
        last_deposit: 0,
        last_withdraw: 0,
        interest_rate: 500, // Default 5%
        is_completed: group.is_completed,
        is_withdrawn: false,
    };

    let plan_key = DataKey::SavingsPlan(user.clone(), group_id);
    env.storage().persistent().set(&plan_key, &savings_plan);

    // Extend TTL for group and user data
    ttl::extend_group_ttl(env, group_id);
    ttl::extend_user_ttl(env, &user);
    ttl::extend_plan_ttl(env, &plan_key);

    // Emit event for joining group
    env.events()
        .publish((soroban_sdk::symbol_short!("grp_join"), user), group_id);

    Ok(())
}

/// Allows a group member to contribute funds to the group savings plan.
///
/// # Arguments
/// * `env` - The contract environment
/// * `user` - The address of the user contributing
/// * `group_id` - The ID of the group
/// * `amount` - The amount to contribute (must be > 0)
///
/// # Returns
/// `Ok(())` on success
/// `Err(SavingsError)` if:
/// - Amount is invalid (<= 0)
/// - User is not a member
/// - Group doesn't exist
pub fn contribute_to_group_save(
    env: &Env,
    user: Address,
    group_id: u64,
    amount: i128,
) -> Result<(), SavingsError> {
    ensure_not_paused(env)?;
    // Validate amount > 0
    if amount <= 0 {
        return Err(SavingsError::InvalidAmount);
    }

    // Fetch the group
    let group_key = DataKey::GroupSave(group_id);
    let mut group: GroupSave = env
        .storage()
        .persistent()
        .get(&group_key)
        .ok_or(SavingsError::PlanNotFound)?;

    // Check if user is a member
    let members_key = DataKey::GroupMembers(group_id);
    let members: Vec<Address> = env
        .storage()
        .persistent()
        .get(&members_key)
        .ok_or(SavingsError::NotGroupMember)?;

    let mut is_member = false;
    for i in 0..members.len() {
        if let Some(member) = members.get(i) {
            if member == user {
                is_member = true;
                break;
            }
        }
    }

    if !is_member {
        return Err(SavingsError::NotGroupMember);
    }

    // Update user's contribution
    let contribution_key = DataKey::GroupMemberContribution(group_id, user.clone());
    let current_contribution: i128 = env
        .storage()
        .persistent()
        .get(&contribution_key)
        .unwrap_or(0i128);
    let new_contribution = current_contribution + amount;
    env.storage()
        .persistent()
        .set(&contribution_key, &new_contribution);

    // Update group's current_amount
    group.current_amount += amount;

    // Check if goal is reached
    if group.current_amount >= group.target_amount {
        group.is_completed = true;
    }

    // Save updated group
    env.storage().persistent().set(&group_key, &group);

    // Update the user's SavingsPlan to reflect the new balance
    let plan_key = DataKey::SavingsPlan(user.clone(), group_id);
    if let Some(mut plan) = env
        .storage()
        .persistent()
        .get::<DataKey, crate::storage_types::SavingsPlan>(&plan_key)
    {
        plan.balance += amount;
        plan.is_completed = group.is_completed;
        plan.last_deposit = env.ledger().timestamp();
        env.storage().persistent().set(&plan_key, &plan);
    } else {
        // If the user doesn't have a SavingsPlan yet (shouldn't happen for group members), create one
        let now = env.ledger().timestamp();
        let plan = crate::storage_types::SavingsPlan {
            plan_id: group_id,
            plan_type: crate::storage_types::PlanType::Group(
                group_id,
                group.is_public,
                group.contribution_type,
                group.target_amount,
            ),
            balance: amount,
            start_time: now,
            last_deposit: now,
            last_withdraw: 0,
            interest_rate: 500,
            is_completed: group.is_completed,
            is_withdrawn: false,
        };
        env.storage().persistent().set(&plan_key, &plan);
    }

    // Award deposit points
    crate::rewards::storage::award_deposit_points(env, user.clone(), amount)?;

    // Extend TTL on contribution
    ttl::extend_group_ttl(env, group_id);
    ttl::extend_user_ttl(env, &user);
    ttl::extend_plan_ttl(env, &plan_key);

    // Emit event for contribution
    env.events().publish(
        (soroban_sdk::symbol_short!("grp_cont"), user, group_id),
        amount,
    );

    Ok(())
}

/// VIEW FUNCTION - Gets a member's contribution to a group
///
/// # Arguments
/// * `env` - The contract environment
/// * `group_id` - The group ID
/// * `user` - The user address
///
/// # Returns
/// The member's total contribution amount
pub fn get_member_contribution(env: &Env, group_id: u64, user: &Address) -> i128 {
    let contribution_key = DataKey::GroupMemberContribution(group_id, user.clone());
    env.storage()
        .persistent()
        .get(&contribution_key)
        .unwrap_or(0i128)
}

/// VIEW FUNCTION - Gets all members of a group
///
/// # Arguments
/// * `env` - The contract environment
/// * `group_id` - The group ID
///
/// # Returns
/// A vector of member addresses
pub fn get_group_members(env: &Env, group_id: u64) -> Vec<Address> {
    let members_key = DataKey::GroupMembers(group_id);
    env.storage()
        .persistent()
        .get(&members_key)
        .unwrap_or(Vec::new(env))
}

/// Helper function to remove a group ID from a user's list of groups.
///
/// # Arguments
/// * `env` - The contract environment
/// * `user` - The user address
/// * `group_id` - The group ID to remove
///
/// # Returns
/// `Ok(())` on success
fn remove_group_from_user_list(
    env: &Env,
    user: &Address,
    group_id: u64,
) -> Result<(), SavingsError> {
    let key = DataKey::UserGroupSaves(user.clone());
    let groups: Vec<u64> = env
        .storage()
        .persistent()
        .get(&key)
        .unwrap_or(Vec::new(env));

    // Create a new vector without the group_id
    let mut new_groups = Vec::new(env);
    for i in 0..groups.len() {
        if let Some(gid) = groups.get(i) {
            if gid != group_id {
                new_groups.push_back(gid);
            }
        }
    }

    env.storage().persistent().set(&key, &new_groups);
    Ok(())
}

/// Allows a user to break or leave a Group Save plan before it is completed.
///
/// This function handles:
/// - Removing the user from the group member list
/// - Refunding the user's contributions
/// - Updating group state (member count, current amount)
/// - Cleaning up all related storage entries
///
/// # Arguments
/// * `env` - The contract environment
/// * `user` - The address of the user leaving the group
/// * `group_id` - The ID of the group to leave
///
/// # Returns
/// `Ok(())` on success
/// `Err(SavingsError)` if:
/// - User doesn't exist
/// - Group doesn't exist
/// - User is not a member of the group
/// - Group is already completed
pub fn break_group_save(env: &Env, user: Address, group_id: u64) -> Result<(), SavingsError> {
    ensure_not_paused(env)?;

    // Ensure user exists
    if !users::user_exists(env, &user) {
        return Err(SavingsError::UserNotFound);
    }

    // Fetch the group
    let group_key = DataKey::GroupSave(group_id);
    let mut group: GroupSave = env
        .storage()
        .persistent()
        .get(&group_key)
        .ok_or(SavingsError::PlanNotFound)?;

    // Check that the group is not already completed
    if group.is_completed {
        return Err(SavingsError::PlanCompleted);
    }

    // Check if user is a member
    let members_key = DataKey::GroupMembers(group_id);
    let members: Vec<Address> = env
        .storage()
        .persistent()
        .get(&members_key)
        .ok_or(SavingsError::NotGroupMember)?;

    let mut is_member = false;
    let mut member_index: Option<u32> = None;

    for i in 0..members.len() {
        if let Some(member) = members.get(i) {
            if member == user {
                is_member = true;
                member_index = Some(i);
                break;
            }
        }
    }

    if !is_member {
        return Err(SavingsError::NotGroupMember);
    }

    // Remove user from members list
    let mut new_members = Vec::new(env);
    for i in 0..members.len() {
        if Some(i) != member_index {
            if let Some(member) = members.get(i) {
                new_members.push_back(member);
            }
        }
    }
    env.storage().persistent().set(&members_key, &new_members);

    // Decrement member count
    group.member_count = group.member_count.saturating_sub(1);

    // Get user's contribution
    let contribution_key = DataKey::GroupMemberContribution(group_id, user.clone());
    let user_contribution: i128 = env
        .storage()
        .persistent()
        .get(&contribution_key)
        .unwrap_or(0i128);

    // Update group's current_amount
    group.current_amount = group.current_amount.saturating_sub(user_contribution);

    // Save updated group
    env.storage().persistent().set(&group_key, &group);

    // Remove user's contribution entry
    env.storage().persistent().remove(&contribution_key);

    // Remove group from user's list of groups
    remove_group_from_user_list(env, &user, group_id)?;

    // Delete user's SavingsPlan for this group
    let plan_key = DataKey::SavingsPlan(user.clone(), group_id);
    env.storage().persistent().remove(&plan_key);

    // Extend TTL for group (still active for other members)
    ttl::extend_group_ttl(env, group_id);

    // Emit event for leaving group
    env.events().publish(
        (soroban_sdk::symbol_short!("grp_leave"), user, group_id),
        user_contribution,
    );

    Ok(())
}
