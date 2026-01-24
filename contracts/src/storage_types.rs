use soroban_sdk::{contracttype, Address, Symbol};

/// Represents the different types of savings plans available in Nestera
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlanType {
    Flexi,
    Lock(u64),
    Goal(Symbol, i128, u32),
    Group(u64, bool, u32, i128),
}

/// Represents a group savings plan with multiple members
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupSave {
    pub group_id: u64,
    pub is_public: bool,
    pub target_amount: i128,
    pub current_amount: i128,
    pub member_count: u32,
    pub max_members: u32,
    pub contribution_type: u32,
    pub creator: Address,
    pub is_completed: bool,
    pub created_at: u64,
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
    /// Maps a group_id to a GroupSave
    GroupSave(u64),
    /// Maps (group_id, user) to their contribution amount
    GroupMemberContribution(u64, Address),
    /// Maps (user, group_id) to track user's group memberships
    UserGroupMembership(Address, u64),
    /// Counter for generating unique group IDs
    GroupIdCounter,
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
