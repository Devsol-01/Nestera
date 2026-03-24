use crate::errors::SavingsError;
use crate::storage_types::DataKey;
use soroban_sdk::{contracttype, symbol_short, Address, Env};

/// Maximum fee in basis points (100% = 10000 bps)
const MAX_FEE_BPS: u32 = 10_000;

/// Global configuration for the Nestera protocol.
///
/// This struct is assembled from individual storage keys rather than
/// stored as a single blob, allowing each field to be updated independently.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub admin: Address,
    pub treasury: Address, // Treasury Address
    pub deposit_fee_bps: u32,
    pub withdrawal_fee_bps: u32,
    pub performance_fee_bps: u32,
    pub paused: bool,
}

// ========== Admin Verification ==========

/// Verifies that `caller` matches the stored admin address.
///
/// # Errors
/// * `SavingsError::Unauthorized` - If the caller is not the admin
fn require_admin(env: &Env, caller: &Address) -> Result<(), SavingsError> {
    let stored_admin: Address = env
        .storage()
        .instance()
        .get(&DataKey::Admin)
        .ok_or(SavingsError::Unauthorized)?;
    if stored_admin != *caller {
        return Err(SavingsError::Unauthorized);
    }
    caller.require_auth();
    Ok(())
}

// ========== Config Functions ==========

/// Initializes the global protocol configuration.
///
/// This can only be called once. If config has already been initialized,
/// it will return `ConfigAlreadyInitialized`.
///
/// # Arguments
/// * `env` - The contract environment
/// * `admin` - The admin address (must match the contract admin)
/// * `treasury` - The protocol treasury address for fee collection
/// * `protocol_fee_bps` - The protocol fee in basis points (0-10000)
///
/// # Errors
/// * `SavingsError::ConfigAlreadyInitialized` - If already initialized
/// * `SavingsError::Unauthorized` - If caller is not the admin
/// * `SavingsError::InvalidFeeBps` - If fee exceeds 10000 bps
pub fn initialize_config(
    env: &Env,
    admin: Address,
    treasury: Address,
    deposit_fee_bps: u32,
    withdrawal_fee_bps: u32,
    performance_fee_bps: u32,
) -> Result<(), SavingsError> {
    // Prevent re-initialization
    let already_init: bool = env
        .storage()
        .instance()
        .get(&DataKey::ConfigInitialized)
        .unwrap_or(false);
    if already_init {
        return Err(SavingsError::ConfigAlreadyInitialized);
    }

    // Verify admin
    require_admin(env, &admin)?;

    // Validate fee bounds
    if deposit_fee_bps > MAX_FEE_BPS
        || withdrawal_fee_bps > MAX_FEE_BPS
        || performance_fee_bps > MAX_FEE_BPS
    {
        return Err(SavingsError::InvalidFeeBps);
    }

    // Store config values
    env.storage()
        .instance()
        .set(&DataKey::TreasuryAddress, &treasury);
    env.storage()
        .instance()
        .set(&DataKey::DepositFeeBps, &deposit_fee_bps);
    env.storage()
        .instance()
        .set(&DataKey::WithdrawalFeeBps, &withdrawal_fee_bps);
    env.storage()
        .instance()
        .set(&DataKey::PerformanceFeeBps, &performance_fee_bps);
    env.storage()
        .instance()
        .set(&DataKey::ConfigInitialized, &true);

    // Initialize the treasury struct with default zero values
    crate::treasury::initialize_treasury(env);

    env.events()
        .publish((symbol_short!("cfg_init"),), performance_fee_bps);

    Ok(())
}

/// Retrieves the current global configuration by assembling values
/// from individual storage keys.
///
/// # Arguments
/// * `env` - The contract environment
///
/// # Returns
/// The assembled `Config` struct
///
/// # Errors
/// * `SavingsError::Unauthorized` - If admin is not set (contract uninitialized)
pub fn get_config(env: &Env) -> Result<Config, SavingsError> {
    let admin: Address = env
        .storage()
        .instance()
        .get(&DataKey::Admin)
        .ok_or(SavingsError::Unauthorized)?;

    let treasury: Address = env
        .storage()
        .instance()
        .get(&DataKey::TreasuryAddress)
        .unwrap_or(admin.clone());

    let deposit_fee_bps: u32 = env
        .storage()
        .instance()
        .get(&DataKey::DepositFeeBps)
        .unwrap_or(0);

    let withdrawal_fee_bps: u32 = env
        .storage()
        .instance()
        .get(&DataKey::WithdrawalFeeBps)
        .unwrap_or(0);

    let performance_fee_bps: u32 = env
        .storage()
        .instance()
        .get(&DataKey::PerformanceFeeBps)
        .unwrap_or(0);

    let paused: bool = env
        .storage()
        .persistent()
        .get(&DataKey::Paused)
        .unwrap_or(false);

    Ok(Config {
        admin,
        treasury,
        deposit_fee_bps,
        withdrawal_fee_bps,
        performance_fee_bps,
        paused,
    })
}

/// Updates the protocol treasury address.
///
/// # Arguments
/// * `env` - The contract environment
/// * `admin` - The admin calling this function
/// * `new_treasury` - The new treasury address
///
/// # Errors
/// * `SavingsError::Unauthorized` - If caller is not the admin
pub fn set_treasury(env: &Env, admin: Address, new_treasury: Address) -> Result<(), SavingsError> {
    require_admin(env, &admin)?;

    env.storage()
        .instance()
        .set(&DataKey::TreasuryAddress, &new_treasury);

    env.events()
        .publish((symbol_short!("set_trs"),), new_treasury);

    Ok(())
}

/// Updates the protocol fee in basis points.
///
/// # Arguments
/// * `env` - The contract environment
/// * `admin` - The admin calling this function
/// * `new_fee_bps` - The new fee in basis points (0-10000)
///
/// # Errors
/// * `SavingsError::Unauthorized` - If caller is not the admin
/// * `SavingsError::InvalidFeeBps` - If fee exceeds 10000 bps
pub fn set_fees(
    env: &Env,
    admin: Address,
    deposit_fee: u32,
    withdrawal_fee: u32,
    performance_fee: u32,
) -> Result<(), SavingsError> {
    require_admin(env, &admin)?;

    if deposit_fee > MAX_FEE_BPS || withdrawal_fee > MAX_FEE_BPS || performance_fee > MAX_FEE_BPS {
        return Err(SavingsError::InvalidFeeBps);
    }

    env.storage()
        .instance()
        .set(&DataKey::DepositFeeBps, &deposit_fee);
    env.storage()
        .instance()
        .set(&DataKey::WithdrawalFeeBps, &withdrawal_fee);
    env.storage()
        .instance()
        .set(&DataKey::PerformanceFeeBps, &performance_fee);

    env.events()
        .publish((symbol_short!("set_fee"),), performance_fee);

    Ok(())
}

/// Pauses the contract, blocking all state-changing operations.
///
/// # Arguments
/// * `env` - The contract environment
/// * `admin` - The admin calling this function
///
/// # Errors
/// * `SavingsError::Unauthorized` - If caller is not the admin
pub fn pause_contract(env: &Env, admin: Address) -> Result<(), SavingsError> {
    require_admin(env, &admin)?;

    env.storage().persistent().set(&DataKey::Paused, &true);

    env.events().publish((symbol_short!("pause"),), admin);

    Ok(())
}

/// Unpauses the contract, restoring all state-changing operations.
///
/// # Arguments
/// * `env` - The contract environment
/// * `admin` - The admin calling this function
///
/// # Errors
/// * `SavingsError::Unauthorized` - If caller is not the admin
pub fn unpause_contract(env: &Env, admin: Address) -> Result<(), SavingsError> {
    require_admin(env, &admin)?;

    env.storage().persistent().set(&DataKey::Paused, &false);

    env.events().publish((symbol_short!("unpause"),), admin);

    Ok(())
}

/// Helper to check if the contract is currently paused.
///
/// This should be called at the entry point of every state-changing
/// function (deposit, withdraw, autosave execution, etc.).
///
/// # Errors
/// * `SavingsError::ContractPaused` - If the contract is paused
pub fn require_not_paused(env: &Env) -> Result<(), SavingsError> {
    let is_paused: bool = env
        .storage()
        .persistent()
        .get(&DataKey::Paused)
        .unwrap_or(false);
    if is_paused {
        Err(SavingsError::ContractPaused)
    } else {
        Ok(())
    }
}
