use soroban_sdk::contracttype;

/// Represents the global state of the Nestera protocol treasury
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Treasury {
    pub total_fees_collected: i128,
    pub total_yield_earned: i128,
    pub reserve_balance: i128,
    pub treasury_balance: i128,
    pub rewards_balance: i128,
    pub operations_balance: i128,
}

impl Default for Treasury {
    fn default() -> Self {
        Self::new()
    }
}

impl Treasury {
    pub fn new() -> Self {
        Self {
            total_fees_collected: 0,
            total_yield_earned: 0,
            reserve_balance: 0,
            treasury_balance: 0,
            rewards_balance: 0,
            operations_balance: 0,
        }
    }
}

/// Contains allocation percentages for the treasury split
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationConfig {
    pub reserve_percent: u32,
    pub rewards_percent: u32,
    pub operations_percent: u32,
}

impl AllocationConfig {
    pub fn default_allocation() -> Self {
        Self {
            reserve_percent: 40_00,    // 40%
            rewards_percent: 40_00,    // 40%
            operations_percent: 20_00, // 20%
        }
    }
}
