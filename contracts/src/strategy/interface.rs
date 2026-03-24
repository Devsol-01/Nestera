/// Yield Strategy Interface for Nestera Protocol
///
/// External strategy contracts must implement this interface to be compatible
/// with the Nestera savings protocol. Strategies are invoked via Soroban
/// cross-contract calls through the strategy registry.
///
/// # Security Assumptions
/// - Strategy contracts are audited and registered via governance/admin.
/// - All state updates in Nestera happen BEFORE external strategy calls (CEI pattern).
/// - Strategy contracts must not hold user funds beyond what is deposited via `deposit`.
/// - `get_total_balance` must reflect the actual deposited principal + any accrued yield.
/// - `withdraw` must return exactly the requested amount or revert.
/// - `harvest` collects accrued yield and returns the harvested amount.
use soroban_sdk::{contractclient, Address, Env};

/// Client interface for external yield strategy contracts.
///
/// Any contract registered as a yield strategy must expose these entry points.
/// The `contractclient` macro generates a `YieldStrategyClient` that can be used
/// for cross-contract invocation on Soroban.
#[contractclient(name = "YieldStrategyClient")]
pub trait YieldStrategy {
    /// Deposits funds into the yield strategy.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `from` - The address depositing (the Nestera contract)
    /// * `amount` - The amount of tokens to deposit (must be > 0)
    ///
    /// # Returns
    /// The number of strategy shares minted for this deposit.
    fn strategy_deposit(env: Env, from: Address, amount: i128) -> i128;

    /// Withdraws funds from the yield strategy.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `to` - The address to receive withdrawn funds
    /// * `amount` - The amount of tokens to withdraw (must be > 0)
    ///
    /// # Returns
    /// The actual amount of tokens returned.
    fn strategy_withdraw(env: Env, to: Address, amount: i128) -> i128;

    /// Harvests accrued yield from the strategy.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `to` - The address to receive harvested yield
    ///
    /// # Returns
    /// The amount of yield harvested.
    fn strategy_harvest(env: Env, to: Address) -> i128;

    /// Returns the total balance held by this strategy for the caller.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `addr` - The address to query balance for
    ///
    /// # Returns
    /// The total balance (principal + accrued yield) denominated in the deposit token.
    fn strategy_balance(env: Env, addr: Address) -> i128;
}
