use soroban_sdk::{contracttype, Address, Symbol};

/// User account data structure
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct User {
    /// Total balance across all savings
    pub total_balance: i128,
    /// Number of active savings accounts
    pub savings_count: u32,
}

impl User {
    /// Create a new user with zero balances
    pub fn new() -> Self {
        User {
            total_balance: 0,
            savings_count: 0,
        }
    }
}

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



/// Storage keys for the contract's persistent data
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    Admin,
    User(Address),
    /// Maps a (user address, plan_id) tuple to a SavingsPlan
    SavingsPlan(Address, u64),
}

