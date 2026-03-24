use crate::errors::SavingsError;
use crate::governance;
use crate::ttl;
use soroban_sdk::{contracttype, symbol_short, Address, Env, Vec};

/// Information about a registered yield strategy.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrategyInfo {
    /// The on-chain address of the strategy contract
    pub address: Address,
    /// Whether this strategy is currently enabled for deposits
    pub enabled: bool,
    /// Risk level indicator (0 = lowest risk, 255 = highest risk)
    pub risk_level: u32,
}

/// Storage keys for the strategy registry.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StrategyKey {
    /// Maps a strategy address to its StrategyInfo
    Info(Address),
    /// List of all registered strategy addresses
    AllStrategies,
}

// ========== Admin / Governance Guard ==========

/// Ensures the caller is the admin or governance is active.
fn require_admin_or_governance(env: &Env, caller: &Address) -> Result<(), SavingsError> {
    caller.require_auth();
    governance::validate_admin_or_governance(env, caller)?;
    Ok(())
}

// ========== Registry Functions ==========

/// Registers a new yield strategy.
///
/// Only callable by admin or governance. The strategy is enabled by default.
///
/// # Arguments
/// * `env` - The contract environment
/// * `caller` - Admin or governance caller
/// * `strategy_address` - Address of the strategy contract
/// * `risk_level` - Risk classification (0-255)
///
/// # Errors
/// * `Unauthorized` - If caller is not admin / governance is not active
/// * `StrategyAlreadyRegistered` - If the strategy address is already registered
pub fn register_strategy(
    env: &Env,
    caller: Address,
    strategy_address: Address,
    risk_level: u32,
) -> Result<(), SavingsError> {
    require_admin_or_governance(env, &caller)?;

    let info_key = StrategyKey::Info(strategy_address.clone());

    // Prevent duplicate registration
    if env.storage().persistent().has(&info_key) {
        return Err(SavingsError::StrategyAlreadyRegistered);
    }

    let info = StrategyInfo {
        address: strategy_address.clone(),
        enabled: true,
        risk_level,
    };

    // Store strategy info
    env.storage().persistent().set(&info_key, &info);

    // Add to the list of all strategies
    let list_key = StrategyKey::AllStrategies;
    let mut list: Vec<Address> = env
        .storage()
        .persistent()
        .get(&list_key)
        .unwrap_or(Vec::new(env));
    list.push_back(strategy_address.clone());
    env.storage().persistent().set(&list_key, &list);

    // Extend TTL
    env.storage()
        .persistent()
        .extend_ttl(&info_key, ttl::LOW_THRESHOLD, ttl::EXTEND_TO);
    env.storage()
        .persistent()
        .extend_ttl(&list_key, ttl::LOW_THRESHOLD, ttl::EXTEND_TO);

    env.events().publish(
        (symbol_short!("strat"), symbol_short!("register")),
        strategy_address,
    );

    Ok(())
}

/// Disables a previously registered strategy.
///
/// Disabled strategies will not accept new deposits but existing positions
/// can still be withdrawn.
///
/// # Arguments
/// * `env` - The contract environment
/// * `caller` - Admin or governance caller
/// * `strategy_address` - Address of the strategy to disable
///
/// # Errors
/// * `Unauthorized` - If caller is not admin / governance is not active
/// * `StrategyNotFound` - If the strategy is not registered
pub fn disable_strategy(
    env: &Env,
    caller: Address,
    strategy_address: Address,
) -> Result<(), SavingsError> {
    require_admin_or_governance(env, &caller)?;

    let info_key = StrategyKey::Info(strategy_address.clone());
    let mut info: StrategyInfo = env
        .storage()
        .persistent()
        .get(&info_key)
        .ok_or(SavingsError::StrategyNotFound)?;

    info.enabled = false;
    env.storage().persistent().set(&info_key, &info);

    env.storage()
        .persistent()
        .extend_ttl(&info_key, ttl::LOW_THRESHOLD, ttl::EXTEND_TO);

    env.events().publish(
        (symbol_short!("strat"), symbol_short!("disable")),
        strategy_address,
    );

    Ok(())
}

/// Retrieves information about a registered strategy.
///
/// # Arguments
/// * `env` - The contract environment
/// * `strategy_address` - Address of the strategy to query
///
/// # Returns
/// `Ok(StrategyInfo)` with the strategy metadata, or `Err(StrategyNotFound)`
pub fn get_strategy(env: &Env, strategy_address: Address) -> Result<StrategyInfo, SavingsError> {
    let info_key = StrategyKey::Info(strategy_address);
    env.storage()
        .persistent()
        .get(&info_key)
        .ok_or(SavingsError::StrategyNotFound)
}

/// Returns the list of all registered strategy addresses.
pub fn get_all_strategies(env: &Env) -> Vec<Address> {
    let list_key = StrategyKey::AllStrategies;
    env.storage()
        .persistent()
        .get(&list_key)
        .unwrap_or(Vec::new(env))
}
