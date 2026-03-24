use super::storage::get_user_rewards;
use super::storage_types::RewardsDataKey;
use soroban_sdk::{Address, Env, Vec};

/// Maximum number of users to consider for ranking calculations
/// Limits iteration to prevent excessive gas usage
const MAX_RANKING_USERS: u32 = 1000;

/// Represents a user's ranking entry
#[derive(Clone, Debug)]
pub struct RankingEntry {
    pub user: Address,
    pub total_points: u128,
    pub rank: u32,
}

/// Retrieves the list of all tracked users for ranking purposes
fn get_all_ranked_users(env: &Env) -> Vec<Address> {
    let key = RewardsDataKey::AllUsers;
    env.storage()
        .persistent()
        .get(&key)
        .unwrap_or_else(|| Vec::new(env))
}

/// Adds a user to the ranked users list if not already present
/// Called internally when rewards are first awarded to a user
pub fn track_user_for_ranking(env: &Env, user: Address) {
    let key = RewardsDataKey::AllUsers;
    let mut users = get_all_ranked_users(env);

    // Check if user already tracked
    for i in 0..users.len() {
        if users.get(i).unwrap() == user {
            return; // Already tracked
        }
    }

    // Add new user
    users.push_back(user);
    env.storage().persistent().set(&key, &users);
}

/// Gets the top N users by total reward points
///
/// # Arguments
/// * `env` - The contract environment
/// * `limit` - Maximum number of users to return (capped at MAX_RANKING_USERS)
///
/// # Returns
/// Vec of (Address, points) tuples sorted by points descending
pub fn get_top_users(env: &Env, limit: u32) -> Vec<(Address, u128)> {
    let users = get_all_ranked_users(env);
    let effective_limit = limit.min(MAX_RANKING_USERS).min(users.len());

    // Build list of (user, points) tuples
    let mut user_points = Vec::new(env);
    for i in 0..users.len().min(MAX_RANKING_USERS) {
        let user = users.get(i).unwrap();
        let rewards = get_user_rewards(env, user.clone());
        if rewards.total_points > 0 {
            user_points.push_back((user, rewards.total_points));
        }
    }

    // Sort by points (descending) using bubble sort for simplicity
    // Note: This is O(n²) but acceptable for limited user sets
    let len = user_points.len();
    for i in 0..len {
        for j in 0..(len - i - 1) {
            let current = user_points.get(j).unwrap();
            let next = user_points.get(j + 1).unwrap();
            if current.1 < next.1 {
                // Swap
                user_points.set(j, next);
                user_points.set(j + 1, current);
            }
        }
    }

    // Take top N
    let mut result = Vec::new(env);
    for i in 0..effective_limit.min(user_points.len()) {
        result.push_back(user_points.get(i).unwrap());
    }

    result
}

/// Gets the rank of a specific user
///
/// # Arguments
/// * `env` - The contract environment
/// * `user` - The user address to rank
///
/// # Returns
/// Rank (1-indexed) or 0 if user has no points or is not ranked
pub fn get_user_rank(env: &Env, user: &Address) -> u32 {
    let users = get_all_ranked_users(env);

    // Build list of all users with points
    let mut user_points = Vec::new(env);
    for i in 0..users.len().min(MAX_RANKING_USERS) {
        let current_user = users.get(i).unwrap();
        let rewards = get_user_rewards(env, current_user.clone());
        if rewards.total_points > 0 {
            user_points.push_back((current_user, rewards.total_points));
        }
    }

    // Sort by points descending
    let len = user_points.len();
    for i in 0..len {
        for j in 0..(len - i - 1) {
            let current = user_points.get(j).unwrap();
            let next = user_points.get(j + 1).unwrap();
            if current.1 < next.1 {
                user_points.set(j, next);
                user_points.set(j + 1, current);
            }
        }
    }

    // Find user's position
    for i in 0..user_points.len() {
        let entry = user_points.get(i).unwrap();
        if entry.0 == *user {
            return i + 1; // 1-indexed rank
        }
    }

    0 // Not ranked or no points
}

/// Gets detailed ranking information for a specific user
///
/// # Returns
/// (rank, total_points, total_users) or None if user has no points
pub fn get_user_ranking_details(env: &Env, user: &Address) -> Option<(u32, u128, u32)> {
    let rewards = get_user_rewards(env, user.clone());
    if rewards.total_points == 0 {
        return None;
    }

    let rank = get_user_rank(env, user);
    if rank == 0 {
        return None;
    }

    let users = get_all_ranked_users(env);
    let total_users = users.len().min(MAX_RANKING_USERS);

    Some((rank, rewards.total_points, total_users))
}
