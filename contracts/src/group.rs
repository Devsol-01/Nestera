use soroban_sdk::{Address, Env};

use crate::errors::SavingsError;
use crate::storage_types::{DataKey, GroupSave};
use crate::users;

/// Allows a user to join a public group savings plan
///
/// # Arguments
/// * `env` - The contract environment
/// * `user` - The address of the user joining the group
/// * `group_id` - The ID of the group to join
///
/// # Returns
/// `Ok(())` on success, or a `SavingsError` if validation fails
///
/// # Errors
/// - `UserNotFound` - User doesn't exist in the system
/// - `PlanNotFound` - Group with the specified ID doesn't exist
/// - `GroupFull` - Group has reached maximum member capacity
/// - `NotGroupMember` - For private groups where user is not invited
pub fn join_group_save(env: &Env, user: Address, group_id: u64) -> Result<(), SavingsError> {
    // Require authorization from the user
    user.require_auth();

    // 1. Ensure user exists
    if !users::user_exists(env, &user) {
        return Err(SavingsError::UserNotFound);
    }

    // 2. Fetch the GroupSave by group_id
    let group_key = DataKey::GroupSave(group_id);
    let mut group: GroupSave = env
        .storage()
        .persistent()
        .get(&group_key)
        .ok_or(SavingsError::PlanNotFound)?;

    // 3. Validate that the group is public (private group invitation logic can be added later)
    if !group.is_public {
        return Err(SavingsError::NotGroupMember);
    }

    // 4. Check if group is full
    if group.member_count >= group.max_members {
        return Err(SavingsError::GroupFull);
    }

    // 5. Check if user is already a member
    let membership_key = DataKey::UserGroupMembership(user.clone(), group_id);
    if env.storage().persistent().has(&membership_key) {
        return Err(SavingsError::UserAlreadyExists);
    }

    // 6. Add the user to the group member list
    // Mark user as member with 0 initial contribution
    let contribution_key = DataKey::GroupMemberContribution(group_id, user.clone());
    env.storage().persistent().set(&contribution_key, &0i128);

    // 7. Increment member_count
    group.member_count += 1;

    // 8. Update group in storage
    env.storage().persistent().set(&group_key, &group);

    // 9. Update UserGroupMembership for the user
    env.storage().persistent().set(&membership_key, &true);

    Ok(())
}

/// Allows a group member to contribute funds to the group savings plan
///
/// # Arguments
/// * `env` - The contract environment
/// * `user` - The address of the user making the contribution
/// * `group_id` - The ID of the group to contribute to
/// * `amount` - The amount to contribute
///
/// # Returns
/// `Ok(())` on success, or a `SavingsError` if validation fails
///
/// # Errors
/// - `InvalidAmount` - Amount is zero or negative
/// - `UserNotFound` - User doesn't exist in the system
/// - `PlanNotFound` - Group with the specified ID doesn't exist
/// - `NotGroupMember` - User is not a member of the group
pub fn contribute_to_group_save(
    env: &Env,
    user: Address,
    group_id: u64,
    amount: i128,
) -> Result<(), SavingsError> {
    // Require authorization from the user
    user.require_auth();

    // 1. Validate amount > 0
    if amount <= 0 {
        return Err(SavingsError::InvalidAmount);
    }

    // 2. Ensure user exists
    if !users::user_exists(env, &user) {
        return Err(SavingsError::UserNotFound);
    }

    // 3. Ensure user is a member of the group
    let membership_key = DataKey::UserGroupMembership(user.clone(), group_id);
    if !env.storage().persistent().has(&membership_key) {
        return Err(SavingsError::NotGroupMember);
    }

    // 4. Fetch the GroupSave
    let group_key = DataKey::GroupSave(group_id);
    let mut group: GroupSave = env
        .storage()
        .persistent()
        .get(&group_key)
        .ok_or(SavingsError::PlanNotFound)?;

    // 5. Update current_amount of the group
    group.current_amount = group
        .current_amount
        .checked_add(amount)
        .ok_or(SavingsError::Overflow)?;

    // 6. Update member's contribution
    let contribution_key = DataKey::GroupMemberContribution(group_id, user.clone());
    let current_contribution: i128 = env
        .storage()
        .persistent()
        .get(&contribution_key)
        .unwrap_or(0);

    let new_contribution = current_contribution
        .checked_add(amount)
        .ok_or(SavingsError::Overflow)?;

    env.storage()
        .persistent()
        .set(&contribution_key, &new_contribution);

    // 7. Check if current_amount >= target_amount and mark is_completed = true
    if group.current_amount >= group.target_amount {
        group.is_completed = true;
    }

    // 8. Update group in storage
    env.storage().persistent().set(&group_key, &group);

    Ok(())
}

/// Get a group by ID
///
/// # Arguments
/// * `env` - The contract environment
/// * `group_id` - The ID of the group to retrieve
///
/// # Returns
/// `Ok(GroupSave)` if found, `Err(SavingsError::PlanNotFound)` otherwise
pub fn get_group(env: &Env, group_id: u64) -> Result<GroupSave, SavingsError> {
    let group_key = DataKey::GroupSave(group_id);
    env.storage()
        .persistent()
        .get(&group_key)
        .ok_or(SavingsError::PlanNotFound)
}

/// Get a member's contribution to a group
///
/// # Arguments
/// * `env` - The contract environment
/// * `group_id` - The ID of the group
/// * `user` - The address of the member
///
/// # Returns
/// The amount contributed by the user, or 0 if not a member
pub fn get_member_contribution(env: &Env, group_id: u64, user: &Address) -> i128 {
    let contribution_key = DataKey::GroupMemberContribution(group_id, user.clone());
    env.storage()
        .persistent()
        .get(&contribution_key)
        .unwrap_or(0)
}

/// Check if a user is a member of a group
///
/// # Arguments
/// * `env` - The contract environment
/// * `user` - The address of the user
/// * `group_id` - The ID of the group
///
/// # Returns
/// `true` if the user is a member, `false` otherwise
pub fn is_group_member(env: &Env, user: &Address, group_id: u64) -> bool {
    let membership_key = DataKey::UserGroupMembership(user.clone(), group_id);
    env.storage().persistent().has(&membership_key)
}

/// Create a new group savings plan
///
/// # Arguments
/// * `env` - The contract environment
/// * `creator` - The address of the user creating the group
/// * `is_public` - Whether the group is public (anyone can join) or private
/// * `target_amount` - The goal amount for the group
/// * `max_members` - Maximum number of members allowed
/// * `contribution_type` - Type of contribution schedule (e.g., 1=weekly, 2=monthly)
///
/// # Returns
/// The ID of the newly created group
pub fn create_group_save(
    env: &Env,
    creator: Address,
    is_public: bool,
    target_amount: i128,
    max_members: u32,
    contribution_type: u32,
) -> Result<u64, SavingsError> {
    // Require authorization from the creator
    creator.require_auth();

    // Validate target amount
    if target_amount <= 0 {
        return Err(SavingsError::InvalidAmount);
    }

    // Validate max_members
    if max_members == 0 {
        return Err(SavingsError::InvalidGroupConfig);
    }

    // Ensure creator exists
    if !users::user_exists(env, &creator) {
        return Err(SavingsError::UserNotFound);
    }

    // Get or initialize group ID counter
    let counter_key = DataKey::GroupIdCounter;
    let group_id: u64 = env
        .storage()
        .persistent()
        .get(&counter_key)
        .unwrap_or(0u64)
        + 1;

    // Update counter
    env.storage().persistent().set(&counter_key, &group_id);

    // Create the group
    let group = GroupSave {
        group_id,
        is_public,
        target_amount,
        current_amount: 0,
        member_count: 1, // Creator is the first member
        max_members,
        contribution_type,
        creator: creator.clone(),
        is_completed: false,
        created_at: env.ledger().timestamp(),
    };

    // Store the group
    let group_key = DataKey::GroupSave(group_id);
    env.storage().persistent().set(&group_key, &group);

    // Add creator as first member
    let contribution_key = DataKey::GroupMemberContribution(group_id, creator.clone());
    env.storage().persistent().set(&contribution_key, &0i128);

    let membership_key = DataKey::UserGroupMembership(creator, group_id);
    env.storage().persistent().set(&membership_key, &true);

    Ok(group_id)
}
