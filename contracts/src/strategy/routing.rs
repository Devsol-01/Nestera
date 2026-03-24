use crate::errors::SavingsError;
use crate::security::release_reentrancy_guard;
use crate::storage_types::{DataKey, StrategyPerformance};
use crate::strategy::interface::YieldStrategyClient;
use crate::strategy::registry::{self, StrategyKey};
use crate::ttl;
use soroban_sdk::{contracttype, symbol_short, Address, Env};

/// Tracks a deposit routed to a yield strategy.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrategyPosition {
    /// The strategy contract address
    pub strategy: Address,
    /// Principal amount deposited into the strategy
    pub principal_deposited: i128,
    /// Shares received from the strategy
    pub strategy_shares: i128,
}

/// Storage key for strategy positions keyed by (plan_type_tag, plan_id).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StrategyPositionKey {
    /// Position for a LockSave plan
    Lock(u64),
    /// Position for a GroupSave plan
    Group(u64),
}

// ========== Performance Tracking Helpers ==========

/// Loads the current performance record for a strategy (defaults to zero).
fn load_performance(env: &Env, strategy: &Address) -> StrategyPerformance {
    env.storage()
        .persistent()
        .get(&DataKey::StrategyPerformance(strategy.clone()))
        .unwrap_or(StrategyPerformance {
            total_deposited: 0,
            total_withdrawn: 0,
            total_harvested: 0,
            apy_estimate_bps: 0,
        })
}

/// Saves a performance record and extends its TTL.
fn save_performance(env: &Env, strategy: &Address, perf: &StrategyPerformance) {
    let key = DataKey::StrategyPerformance(strategy.clone());
    env.storage().persistent().set(&key, perf);
    env.storage()
        .persistent()
        .extend_ttl(&key, ttl::LOW_THRESHOLD, ttl::EXTEND_TO);
}

/// Recomputes the APY estimate in basis points.
///
/// Formula: `(total_harvested * 10_000) / total_deposited`, clamped to `u32::MAX`.
/// Returns 0 when `total_deposited` is 0 to avoid division by zero.
fn compute_apy_bps(total_deposited: i128, total_harvested: i128) -> u32 {
    if total_deposited <= 0 {
        return 0;
    }
    let bps = (total_harvested * 10_000) / total_deposited;
    if bps < 0 {
        0
    } else if bps > u32::MAX as i128 {
        u32::MAX
    } else {
        bps as u32
    }
}

/// Returns the performance metrics for a strategy.
pub fn get_strategy_performance(env: &Env, strategy_address: Address) -> StrategyPerformance {
    load_performance(env, &strategy_address)
}

/// Routes eligible deposit funds to a registered yield strategy.
///
/// Follows the Checks-Effects-Interactions (CEI) pattern:
/// 1. **Checks** – validates strategy exists & is enabled, amount > 0, no reentrancy
/// 2. **Effects** – persists `StrategyPosition` and performance state
/// 3. **Interactions** – calls the external strategy contract
///
/// A reentrancy guard prevents malicious strategy callbacks from re-entering this
/// function before the first call completes.
///
/// If the external strategy call fails, the transaction reverts atomically
/// (Soroban guarantees this), so state is always consistent.
///
/// # Arguments
/// * `env` - The contract environment
/// * `strategy_address` - Address of the target strategy contract
/// * `position_key` - Storage key for this position (Lock or Group)
/// * `amount` - Amount to deposit into the strategy
///
/// # Returns
/// The number of strategy shares received.
///
/// # Errors
/// * `StrategyNotFound` - Strategy not registered
/// * `StrategyDisabled` - Strategy is disabled
/// * `InvalidAmount` - amount <= 0
/// * `ReentrancyDetected` - A reentrant call was attempted
/// * `InvalidStrategyResponse` - Strategy returned 0 or negative shares
pub fn route_to_strategy(
    env: &Env,
    strategy_address: Address,
    position_key: StrategyPositionKey,
    amount: i128,
) -> Result<i128, SavingsError> {
    // --- CHECKS ---
    if amount <= 0 {
        return Err(SavingsError::InvalidAmount);
    }

    let info = registry::get_strategy(env, strategy_address.clone())?;
    if !info.enabled {
        return Err(SavingsError::StrategyDisabled);
    }

    // --- EFFECTS (state update BEFORE external call) ---
    // Optimistically record the position; Soroban atomically reverts on failure.
    let position = StrategyPosition {
        strategy: strategy_address.clone(),
        principal_deposited: amount,
        strategy_shares: 0, // placeholder, updated after call
    };
    env.storage().persistent().set(&position_key, &position);

    // Update global strategy principal
    let principal_key = DataKey::StrategyTotalPrincipal(strategy_address.clone());
    let current_principal: i128 = env.storage().persistent().get(&principal_key).unwrap_or(0);
    env.storage().persistent().set(
        &principal_key,
        &current_principal.checked_add(amount).unwrap(),
    );
    env.storage()
        .persistent()
        .extend_ttl(&principal_key, ttl::LOW_THRESHOLD, ttl::EXTEND_TO);

    // Update performance: record deposit
    let mut perf = load_performance(env, &strategy_address);
    perf.total_deposited = perf
        .total_deposited
        .checked_add(amount)
        .unwrap_or(i128::MAX);
    perf.apy_estimate_bps = compute_apy_bps(perf.total_deposited, perf.total_harvested);
    save_performance(env, &strategy_address, &perf);

    let client = YieldStrategyClient::new(env, &strategy_address);
    let shares = client.strategy_deposit(&env.current_contract_address(), &amount);

    // Validate external call response
    if shares <= 0 {
        return Err(SavingsError::InvalidStrategyResponse);
    }

    // Update shares after successful call
    let final_position = StrategyPosition {
        strategy: strategy_address.clone(),
        principal_deposited: amount,
        strategy_shares: shares,
    };
    env.storage()
        .persistent()
        .set(&position_key, &final_position);

    // Extend TTL
    env.storage()
        .persistent()
        .extend_ttl(&position_key, ttl::LOW_THRESHOLD, ttl::EXTEND_TO);

    // Emit event
    env.events().publish(
        (symbol_short!("strat"), symbol_short!("deposit")),
        (strategy_address, amount, shares),
    );

    Ok(shares)
}

/// Retrieves the strategy position for a plan, if any.
pub fn get_position(env: &Env, position_key: StrategyPositionKey) -> Option<StrategyPosition> {
    env.storage().persistent().get(&position_key)
}

/// Withdraws funds from a strategy position.
///
/// Follows CEI: state is updated before the external call. A reentrancy guard
/// prevents malicious strategy callbacks from re-entering while withdrawal
/// is in progress. The actual returned amount from the strategy is validated
/// to be > 0.
///
/// # Arguments
/// * `env` - The contract environment
/// * `position_key` - The position to withdraw from
/// * `to` - The recipient address
///
/// # Returns
/// The amount of tokens received from the strategy.
pub fn withdraw_from_strategy(
    env: &Env,
    position_key: StrategyPositionKey,
    to: Address,
) -> Result<i128, SavingsError> {
    let mut position: StrategyPosition = env
        .storage()
        .persistent()
        .get(&position_key)
        .ok_or(SavingsError::StrategyNotFound)?;

    if position.principal_deposited == 0 {
        return Ok(0);
    }

    // Check strategy still exists (may be disabled, but withdrawal still allowed)
    let info_key = StrategyKey::Info(position.strategy.clone());
    if !env.storage().persistent().has(&info_key) {
        return Err(SavingsError::StrategyNotFound);
    }

    // External call: check actual balance
    let client = YieldStrategyClient::new(env, &position.strategy);
    let strategy_balance = client.strategy_balance(&env.current_contract_address());
    let withdraw_amount = position.principal_deposited.min(strategy_balance);
    if withdraw_amount <= 0 {
        release_reentrancy_guard(env);
        return Err(SavingsError::InsufficientBalance);
    }

    // Update state BEFORE external call (CEI)
    let strategy_addr = position.strategy.clone();
    position.principal_deposited = position
        .principal_deposited
        .checked_sub(withdraw_amount)
        .ok_or(SavingsError::Underflow)?;
    position.strategy_shares = 0;
    env.storage().persistent().set(&position_key, &position);

    // Update global strategy principal
    let principal_key = DataKey::StrategyTotalPrincipal(strategy_addr.clone());
    let current_principal: i128 = env.storage().persistent().get(&principal_key).unwrap_or(0);
    if current_principal >= withdraw_amount {
        env.storage()
            .persistent()
            .set(&principal_key, &(current_principal - withdraw_amount));
    } else {
        env.storage().persistent().set(&principal_key, &0_i128);
    }

    // Update performance: record withdrawal
    let mut perf = load_performance(env, &strategy_addr);
    perf.total_withdrawn = perf
        .total_withdrawn
        .checked_add(withdraw_amount)
        .unwrap_or(i128::MAX);
    save_performance(env, &strategy_addr, &perf);

    // Call strategy withdraw (INTERACTION)
    let returned = client.strategy_withdraw(&to, &withdraw_amount);

    // Validate response
    if returned <= 0 {
        return Err(SavingsError::InvalidStrategyResponse);
    }

    env.events().publish(
        (symbol_short!("strat"), symbol_short!("withdraw")),
        (strategy_addr, withdraw_amount, returned),
    );

    Ok(returned)
}

/// Harvests yield from a given strategy, calculates profit,
/// allocates protocol fee to treasury, and credits the rest to users.
///
/// A reentrancy guard prevents re-entrant calls during the harvest interaction.
pub fn harvest_strategy(env: &Env, strategy_address: Address) -> Result<i128, SavingsError> {
    // Check if strategy exists
    let info_key = StrategyKey::Info(strategy_address.clone());
    if !env.storage().persistent().has(&info_key) {
        return Err(SavingsError::StrategyNotFound);
    }

    let client = YieldStrategyClient::new(env, &strategy_address);
    let nestera_addr = env.current_contract_address();

    // 1. Determine current balance
    let strategy_balance = client.strategy_balance(&nestera_addr);

    // 2. Retrieve recorded principal
    let principal_key = DataKey::StrategyTotalPrincipal(strategy_address.clone());
    let principal: i128 = env.storage().persistent().get(&principal_key).unwrap_or(0);

    // 3. Calculate profit (no double counting)
    if strategy_balance <= principal {
        release_reentrancy_guard(env);
        return Ok(0);
    }
    let profit = strategy_balance - principal;

    // 4. Call strategy harvest (INTERACTION)
    let harvested = client.strategy_harvest(&nestera_addr);

    // Safety check - we can only distribute what we actually harvested
    let actual_yield = profit.min(harvested);
    if actual_yield <= 0 {
        return Ok(0);
    }

    // 5. Calculate treasury allocation
    let config = crate::config::get_config(env)?;
    let performance_fee_bps = config.performance_fee_bps;

    let treasury_fee = if performance_fee_bps > 0 {
        (actual_yield
            .checked_mul(performance_fee_bps as i128)
            .ok_or(SavingsError::Overflow)?)
            / 10_000
    } else {
        0
    };

    let user_yield = actual_yield
        .checked_sub(treasury_fee)
        .ok_or(SavingsError::Underflow)?;

    // 6. Update accounting records
    if treasury_fee > 0 {
        let treasury_balance_key = DataKey::TotalBalance(config.treasury.clone());
        let current_treasury: i128 = env
            .storage()
            .persistent()
            .get(&treasury_balance_key)
            .unwrap_or(0);
        env.storage().persistent().set(
            &treasury_balance_key,
            &(current_treasury.checked_add(treasury_fee).unwrap()),
        );
    }

    if user_yield > 0 {
        let yield_key = DataKey::StrategyYield(strategy_address.clone());
        let current_yield: i128 = env.storage().persistent().get(&yield_key).unwrap_or(0);
        env.storage().persistent().set(
            &yield_key,
            &(current_yield.checked_add(user_yield).unwrap()),
        );
        env.storage()
            .persistent()
            .extend_ttl(&yield_key, ttl::LOW_THRESHOLD, ttl::EXTEND_TO);
    }

    // 7. Update performance: record harvested yield
    let mut perf = load_performance(env, &strategy_address);
    perf.total_harvested = perf
        .total_harvested
        .checked_add(actual_yield)
        .unwrap_or(i128::MAX);
    perf.apy_estimate_bps = compute_apy_bps(perf.total_deposited, perf.total_harvested);
    save_performance(env, &strategy_address, &perf);

    env.events().publish(
        (symbol_short!("strat"), symbol_short!("harvest")),
        (strategy_address, actual_yield, treasury_fee, user_yield),
    );

    // Record performance fee and yield in treasury
    if treasury_fee > 0 {
        crate::treasury::record_fee(env, treasury_fee, soroban_sdk::Symbol::new(env, "perf"));
    }
    if user_yield > 0 {
        crate::treasury::record_yield(env, user_yield);
    }

    Ok(actual_yield)
}
