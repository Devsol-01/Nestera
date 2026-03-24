use soroban_sdk::{contracttype, Address};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RewardsConfig {
    pub points_per_token: u32,      // e.g., 10 points per 1 token
    pub streak_bonus_bps: u32,      // Bonus for consistent saving
    pub long_lock_bonus_bps: u32,   // Bonus for long-term locks
    pub goal_completion_bonus: u32, // Flat points for finishing a goal
    pub enabled: bool,

    // Anti-farming protections
    pub min_deposit_for_rewards: i128, // Minimum deposit to earn rewards
    pub action_cooldown_seconds: u64,  // Cooldown between rewardable actions
    pub max_daily_points: u128,        // Daily points cap per user
    pub max_streak_multiplier: u32,    // Maximum streak multiplier (in bps)
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserRewards {
    pub total_points: u128,         // Total spendable/accumulated points
    pub lifetime_deposited: i128,   // Total volume for tier calculation
    pub current_streak: u32,        // Number of consecutive periods saved
    pub last_action_timestamp: u64, // To check if streak is broken

    // Anti-farming tracking
    pub daily_points_earned: u128, // Points earned today
    pub last_reward_day: u64,      // Last day rewards were earned (ledger day)
}

#[contracttype]
pub enum RewardsDataKey {
    Config,
    UserLedger(Address),
    AllUsers, // Tracks all users with rewards for ranking
}
