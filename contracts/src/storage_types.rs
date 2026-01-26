use soroban_sdk::{contracttype, Address, String, Symbol};

/// Represents the different types of savings plans available in Nestera
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlanType {
    Flexi,
    Lock(u64),
    Goal(Symbol, i128, u32),
    Group(u64, bool, u32, i128),
}

/// Represents an individual savings plan for a user
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SavingsPlan {
    pub plan_id: u64,
    pub plan_type: PlanType,
    pub balance: i128,
    pub start_time: u64,
    pub last_deposit: u64,
    pub last_withdraw: u64,
    /// Annual Percentage Yield (APY) as an integer (e.g., 500 = 5.00%)
    pub interest_rate: u32,
    pub is_completed: bool,
    pub is_withdrawn: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct User {
    pub total_balance: i128,
    pub savings_count: u32,
}

impl User {
    pub fn new() -> Self {
        Self {
            total_balance: 0,
            savings_count: 0,
        }
    }
}

/// Represents a group savings plan
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupSave {
    pub id: u64,
    pub creator: Address,
    pub title: String,
    pub description: String,
    pub category: String,
    pub target_amount: i128,
    pub current_amount: i128,
    pub contribution_type: u32,
    pub contribution_amount: i128,
    pub is_public: bool,
    pub member_count: u32,
    pub start_time: u64,
    pub end_time: u64,
    pub is_completed: bool,
}

/// Represents a Lock Save plan with fixed duration and maturity
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockSave {
    pub id: u64,
    pub owner: Address,
    pub amount: i128,
    pub interest_rate: u32,
    pub start_time: u64,
    pub maturity_time: u64,
    pub is_withdrawn: bool,
}

/// Represents a Goal Save plan with target amount
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoalSave {
    pub id: u64,
    pub owner: Address,
    pub goal_name: Symbol,
    pub target_amount: i128,
    pub current_amount: i128,
    pub interest_rate: u32,
    pub start_time: u64,
    pub is_completed: bool,
    pub is_withdrawn: bool,
}

/// Storage keys for the contract's persistent data
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    Admin,
    Initialized,
    AdminPublicKey,
    User(Address),
    /// Maps a (user address, plan_id) tuple to a SavingsPlan
    SavingsPlan(Address, u64),
    FlexiBalance(Address),
    TotalBalance(Address),
    /// Maps group ID to GroupSave struct
    GroupSave(u64),
    /// Maps user address to list of GroupSave IDs they participate in
    UserGroupSaves(Address),
    /// Stores the next auto-incrementing GroupSave ID
    NextGroupId,
    /// Maps lock plan ID to LockSave struct
    LockSave(u64),
    /// Maps user to a list of their LockSave IDs
    UserLockSaves(Address),
    /// Stores the next auto-incrementing LockSave ID
    NextLockId,
    /// Maps goal plan ID to GoalSave struct
    GoalSave(u64),
    /// Maps user to a list of their GoalSave IDs
    UserGoalSaves(Address),
    /// Stores the next auto-incrementing GoalSave ID
    NextGoalId,
    /// Maps (group_id, user) to their contribution amount
    GroupMemberContribution(u64, Address),
    /// Maps group_id to list of member addresses
    GroupMembers(u64),
}

/// Payload structure that the admin signs off-chain
/// The user submits this along with the signature to mint tokens
#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct MintPayload {
    /// The user's address who is allowed to mint
    pub user: Address,
    /// The savings level or amount the user is claiming
    pub amount: i128,
    /// Unix timestamp when the signature was created
    pub timestamp: u64,
    /// Expiry duration in seconds (signature valid for timestamp + expiry_duration)
    pub expiry_duration: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct LockSave {
    pub plan_id: u64,
    pub balance: i128,
    pub start_time: u64,
    pub locked_until: u64,
    pub interest_rate: u32,
    pub is_withdrawn: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct GoalSave {
    pub plan_id: u64,
    pub balance: i128,
    pub target_amount: i128,
    pub start_time: u64,
    pub interest_rate: u32,
    pub is_completed: bool,
    pub contribution_type: u32,
    pub goal_name: Symbol,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct GroupSave {
    pub plan_id: u64,
    pub balance: i128,
    pub target_amount: i128,
    pub start_time: u64,
    pub interest_rate: u32,
    pub is_completed: bool,
    pub is_public: bool,
    pub contribution_type: u32,
    pub group_id: u64,
}
