#![no_std]
#![allow(non_snake_case)]
use soroban_sdk::{
    contract, contractimpl, panic_with_error, symbol_short, xdr::ToXdr, Address, Bytes, BytesN,
    Env, String, Symbol, Vec,
};

mod autosave;
mod config;
mod errors;
mod flexi;
mod goal;
mod governance;
mod group;
mod invariants;
mod lock;

pub mod rewards;
mod storage_types;
mod ttl;
mod upgrade;
mod users;

#[cfg(test)]
mod security;

mod rates;
mod views;

pub use crate::config::Config;
pub use crate::errors::SavingsError;
pub use crate::storage_types::{
    AutoSave, DataKey, GoalSave, GoalSaveView, GroupSave, GroupSaveView, LockSave, LockSaveView,
    MintPayload, PlanType, SavingsPlan, User,
};

/// Custom error codes for the contract administration
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ContractError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    InvalidSignature = 3,
    SignatureExpired = 4,
}

impl From<ContractError> for soroban_sdk::Error {
    fn from(e: ContractError) -> Self {
        soroban_sdk::Error::from_contract_error(e as u32)
    }
}

#[contract]
pub struct NesteraContract;

pub(crate) fn ensure_not_paused(env: &Env) -> Result<(), SavingsError> {
    let paused_key = DataKey::Paused;

    // Extend TTL on config check (only if the key exists)
    if env.storage().persistent().has(&paused_key) {
        ttl::extend_config_ttl(env, &paused_key);
    }

    config::require_not_paused(env)
}

pub(crate) fn calculate_fee(amount: i128, fee_bps: u32) -> Result<i128, SavingsError> {
    if fee_bps == 0 {
        return Ok(0);
    }
    // Task 1: Use invariant check for valid fee range
    invariants::assert_valid_fee(fee_bps)?;

    // Task 4: Proper overflow protection
    let total = amount
        .checked_mul(fee_bps as i128)
        .ok_or(SavingsError::Overflow)?;

    Ok(total / 10_000)
}

#[cfg(test)]
mod fee_tests {
    use super::calculate_fee;

    #[test]
    fn test_calculate_fee_zero_bps() {
        assert_eq!(calculate_fee(10_000, 0).unwrap(), 0);
        assert_eq!(calculate_fee(1_000_000, 0).unwrap(), 0);
    }

    #[test]
    fn test_calculate_fee_basic() {
        assert_eq!(calculate_fee(10_000, 1_000).unwrap(), 1_000);
        assert_eq!(calculate_fee(10_000, 500).unwrap(), 500);
    }

    #[test]
    fn test_calculate_fee_rounds_down() {
        // 1.25% of 3,333 = 41.6625, should round down to 41
        assert_eq!(calculate_fee(3_333, 125).unwrap(), 41);
        // 2.5% of 4,875 = 121.875, should round down to 121
        assert_eq!(calculate_fee(4_875, 250).unwrap(), 121);
    }

    #[test]
    fn test_calculate_fee_small_amounts() {
        // 1% of 50 = 0.5, should round down to 0
        assert_eq!(calculate_fee(50, 100).unwrap(), 0);
        // 1% of 99 = 0.99, should round down to 0
        assert_eq!(calculate_fee(99, 100).unwrap(), 0);
        // 1% of 100 = 1
        assert_eq!(calculate_fee(100, 100).unwrap(), 1);
    }

    #[test]
    fn test_calculate_fee_max_bps() {
        // 100% of 10,000 = 10,000
        assert_eq!(calculate_fee(10_000, 10_000).unwrap(), 10_000);
    }

    #[test]
    fn test_calculate_fee_fractional_bps() {
        // 0.01% (1 basis point) of 1,000,000 = 100
        assert_eq!(calculate_fee(1_000_000, 1).unwrap(), 100);
    }
}

#[contractimpl]
impl NesteraContract {
    /// Initialize a new user in the system
    pub fn init_user(env: Env, user: Address) -> User {
        ensure_not_paused(&env).unwrap_or_else(|e| panic_with_error!(&env, e));
        users::initialize_user(&env, user.clone()).unwrap_or_else(|e| panic_with_error!(&env, e));
        users::get_user(&env, &user).unwrap_or_else(|e| panic_with_error!(&env, e))
    }

    pub fn initialize(env: Env, admin: Address, admin_public_key: BytesN<32>) {
        if env.storage().instance().has(&DataKey::Initialized) {
            panic_with_error!(&env, ContractError::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::AdminPublicKey, &admin_public_key);
        env.storage().instance().set(&DataKey::Initialized, &true);
        env.storage().persistent().set(&DataKey::Paused, &false);

        // Extend TTL for paused state
        ttl::extend_config_ttl(&env, &DataKey::Paused);

        // Extend instance TTL
        ttl::extend_instance_ttl(&env);

        env.events()
            .publish((symbol_short!("init"),), admin_public_key);
    }

    pub fn verify_signature(env: Env, payload: MintPayload, signature: BytesN<64>) -> bool {
        if !env.storage().instance().has(&DataKey::Initialized) {
            panic_with_error!(&env, ContractError::NotInitialized);
        }
        let current_timestamp = env.ledger().timestamp();
        let expiry_time = payload.timestamp + payload.expiry_duration;
        if current_timestamp > expiry_time {
            panic_with_error!(&env, ContractError::SignatureExpired);
        }
        let admin_public_key: BytesN<32> = env
            .storage()
            .instance()
            .get(&DataKey::AdminPublicKey)
            .expect("Admin PK not found");
        let payload_bytes: Bytes = payload.to_xdr(&env);
        env.crypto()
            .ed25519_verify(&admin_public_key, &payload_bytes, &signature);
        true
    }

    pub fn mint(env: Env, payload: MintPayload, signature: BytesN<64>) -> i128 {
        Self::verify_signature(env.clone(), payload.clone(), signature);
        let amount = payload.amount;
        env.events()
            .publish((symbol_short!("mint"), payload.user), amount);
        amount
    }

    pub fn is_initialized(env: Env) -> bool {
        env.storage().instance().has(&DataKey::Initialized)
    }

    pub fn create_savings_plan(
        env: Env,
        user: Address,
        plan_type: PlanType,
        initial_deposit: i128,
    ) -> Result<u64, SavingsError> {
        // 1. CHECKS
        ensure_not_paused(&env)?;
        invariants::assert_non_negative(initial_deposit)?;

        rewards::storage::award_deposit_points(&env, user.clone(), initial_deposit)?;

        if !Self::is_initialized(env.clone()) {
            return Err(SavingsError::InternalError);
        }

        let mut user_data = Self::get_user(env.clone(), user.clone()).unwrap_or(User {
            total_balance: 0,
            savings_count: 0,
        });

        // 2. EFFECTS (Using Checked Math)
        user_data.savings_count = user_data
            .savings_count
            .checked_add(1)
            .ok_or(SavingsError::Overflow)?;

        user_data.total_balance = user_data
            .total_balance
            .checked_add(initial_deposit)
            .ok_or(SavingsError::Overflow)?;

        let plan_id = user_data.savings_count as u64;

        let new_plan = SavingsPlan {
            plan_id,
            plan_type,
            balance: initial_deposit,
            start_time: env.ledger().timestamp(),
            last_deposit: env.ledger().timestamp(),
            last_withdraw: 0,
            interest_rate: 500,
            is_completed: false,
            is_withdrawn: false,
        };

        // State updates (Effects)
        env.storage()
            .persistent()
            .set(&DataKey::User(user.clone()), &user_data);
        env.storage()
            .persistent()
            .set(&DataKey::SavingsPlan(user.clone(), plan_id), &new_plan);

        // 3. INTERACTIONS (Events)
        env.events().publish(
            (Symbol::new(&env, "create_plan"), user, plan_id),
            initial_deposit,
        );

        Ok(plan_id)
    }

    // --- User & Flexi Logic ---

    pub fn get_user(env: Env, user: Address) -> Result<User, SavingsError> {
        users::get_user(&env, &user)
    }

    pub fn initialize_user(env: Env, user: Address) -> Result<(), SavingsError> {
        ensure_not_paused(&env)?;
        users::initialize_user(&env, user)
    }

    pub fn user_exists(env: Env, user: Address) -> bool {
        users::user_exists(&env, &user)
    }

    pub fn deposit_flexi(env: Env, user: Address, amount: i128) -> Result<(), SavingsError> {
        ensure_not_paused(&env)?;
        flexi::flexi_deposit(env, user, amount)
    }

    pub fn withdraw_flexi(env: Env, user: Address, amount: i128) -> Result<(), SavingsError> {
        ensure_not_paused(&env)?;
        flexi::flexi_withdraw(env, user, amount)
    }

    pub fn get_flexi_balance(env: Env, user: Address) -> i128 {
        flexi::get_flexi_balance(&env, user).unwrap_or(0)
    }

    // --- Lock Save Logic ---

    pub fn create_lock_save(env: Env, user: Address, amount: i128, duration: u64) -> u64 {
        ensure_not_paused(&env).unwrap_or_else(|e| panic_with_error!(&env, e));
        user.require_auth();
        lock::create_lock_save(&env, user, amount, duration)
            .unwrap_or_else(|e| panic_with_error!(&env, e))
    }

    pub fn withdraw_lock_save(env: Env, user: Address, lock_id: u64) -> i128 {
        ensure_not_paused(&env).unwrap_or_else(|e| panic_with_error!(&env, e));
        user.require_auth();
        lock::withdraw_lock_save(&env, user, lock_id).unwrap_or_else(|e| panic_with_error!(&env, e))
    }

    pub fn check_matured_lock(env: Env, lock_id: u64) -> bool {
        lock::check_matured_lock(&env, lock_id)
    }

    pub fn get_user_lock_saves(env: Env, user: Address) -> Vec<u64> {
        lock::get_user_lock_saves(&env, &user)
    }

    // ========== Goal Save Functions ==========

    pub fn create_goal_save(
        env: Env,
        user: Address,
        goal_name: Symbol,
        target_amount: i128,
        initial_deposit: i128,
    ) -> u64 {
        ensure_not_paused(&env).unwrap_or_else(|e| panic_with_error!(&env, e));
        goal::create_goal_save(&env, user, goal_name, target_amount, initial_deposit)
            .unwrap_or_else(|e| panic_with_error!(&env, e))
    }

    pub fn deposit_to_goal_save(env: Env, user: Address, goal_id: u64, amount: i128) {
        ensure_not_paused(&env).unwrap_or_else(|e| panic_with_error!(&env, e));
        goal::deposit_to_goal_save(&env, user, goal_id, amount)
            .unwrap_or_else(|e| panic_with_error!(&env, e))
    }

    pub fn withdraw_completed_goal_save(env: Env, user: Address, goal_id: u64) -> i128 {
        ensure_not_paused(&env).unwrap_or_else(|e| panic_with_error!(&env, e));
        goal::withdraw_completed_goal_save(&env, user, goal_id)
            .unwrap_or_else(|e| panic_with_error!(&env, e))
    }

    pub fn break_goal_save(env: Env, user: Address, goal_id: u64) -> i128 {
        ensure_not_paused(&env).unwrap_or_else(|e| panic_with_error!(&env, e));
        goal::break_goal_save(&env, user, goal_id).unwrap_or_else(|e| panic_with_error!(&env, e))
    }

    pub fn get_goal_save_detail(env: Env, goal_id: u64) -> GoalSave {
        goal::get_goal_save(&env, goal_id)
            .unwrap_or_else(|| panic_with_error!(&env, SavingsError::PlanNotFound))
    }

    pub fn get_user_goal_saves(env: Env, user: Address) -> Vec<u64> {
        goal::get_user_goal_saves(&env, &user)
    }

    // --- Group Save Logic ---

    pub fn create_group_save(
        env: Env,
        creator: Address,
        title: String,
        description: String,
        category: String,
        target_amount: i128,
        contribution_type: u32,
        contribution_amount: i128,
        is_public: bool,
        start_time: u64,
        end_time: u64,
    ) -> Result<u64, SavingsError> {
        ensure_not_paused(&env)?;
        group::create_group_save(
            &env,
            creator,
            title,
            description,
            category,
            target_amount,
            contribution_type,
            contribution_amount,
            is_public,
            start_time,
            end_time,
        )
    }

    pub fn join_group_save(env: Env, user: Address, group_id: u64) -> Result<(), SavingsError> {
        ensure_not_paused(&env)?;
        group::join_group_save(&env, user, group_id)
    }

    pub fn contribute_to_group_save(
        env: Env,
        user: Address,
        group_id: u64,
        amount: i128,
    ) -> Result<(), SavingsError> {
        ensure_not_paused(&env)?;
        group::contribute_to_group_save(&env, user, group_id, amount)
    }

    pub fn break_group_save(env: Env, user: Address, group_id: u64) -> Result<(), SavingsError> {
        ensure_not_paused(&env)?;
        group::break_group_save(&env, user, group_id)
    }

    // --- Admin Control Functions ---

    pub fn set_admin(
        env: Env,
        current_admin: Address,
        new_admin: Address,
    ) -> Result<(), SavingsError> {
        current_admin.require_auth();
        let stored_admin: Option<Address> = env.storage().instance().get(&DataKey::Admin);
        if let Some(admin) = stored_admin {
            if admin != current_admin {
                return Err(SavingsError::Unauthorized);
            }
        }
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.events()
            .publish((symbol_short!("set_admin"),), new_admin);
        Ok(())
    }

    pub fn set_flexi_rate(env: Env, caller: Address, rate: i128) -> Result<(), SavingsError> {
        rates::set_flexi_rate(&env, caller, rate)
    }

    pub fn set_goal_rate(env: Env, caller: Address, rate: i128) -> Result<(), SavingsError> {
        rates::set_goal_rate(&env, caller, rate)
    }

    pub fn set_group_rate(env: Env, caller: Address, rate: i128) -> Result<(), SavingsError> {
        rates::set_group_rate(&env, caller, rate)
    }

    pub fn set_lock_rate(
        env: Env,
        caller: Address,
        duration_days: u64,
        rate: i128,
    ) -> Result<(), SavingsError> {
        rates::set_lock_rate(&env, caller, duration_days, rate)
    }

    pub fn set_early_break_fee_bps(env: Env, bps: u32) -> Result<(), SavingsError> {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        if bps > 10_000 {
            return Err(SavingsError::InvalidAmount);
        }
        env.storage()
            .instance()
            .set(&DataKey::EarlyBreakFeeBps, &bps);
        env.events().publish((symbol_short!("set_brk"),), bps);
        Ok(())
    }

    pub fn set_fee_recipient(env: Env, recipient: Address) -> Result<(), SavingsError> {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        env.storage()
            .instance()
            .set(&DataKey::FeeRecipient, &recipient);
        env.events().publish((symbol_short!("set_fee"),), recipient);
        Ok(())
    }

    pub fn set_protocol_fee_bps(env: Env, bps: u32) -> Result<(), SavingsError> {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        if bps > 10_000 {
            return Err(SavingsError::InvalidAmount);
        }
        env.storage().instance().set(&DataKey::PlatformFee, &bps);
        env.events().publish((symbol_short!("set_pfee"),), bps);
        Ok(())
    }

    pub fn pause(env: Env, caller: Address) -> Result<(), SavingsError> {
        caller.require_auth();
        governance::validate_admin_or_governance(&env, &caller)?;

        env.storage().persistent().set(&DataKey::Paused, &true);
        ttl::extend_config_ttl(&env, &DataKey::Paused);
        env.events().publish((symbol_short!("pause"), caller), ());
        Ok(())
    }

    pub fn unpause(env: Env, caller: Address) -> Result<(), SavingsError> {
        caller.require_auth();
        governance::validate_admin_or_governance(&env, &caller)?;

        env.storage().persistent().set(&DataKey::Paused, &false);
        ttl::extend_config_ttl(&env, &DataKey::Paused);
        env.events().publish((symbol_short!("unpause"), caller), ());
        Ok(())
    }

    // --- Remaining views and utilities ---
    pub fn get_savings_plan(env: Env, user: Address, plan_id: u64) -> Option<SavingsPlan> {
        env.storage()
            .persistent()
            .get(&DataKey::SavingsPlan(user, plan_id))
    }

    pub fn is_paused(env: Env) -> bool {
        let paused_key = DataKey::Paused;
        let is_paused = env.storage().persistent().get(&paused_key).unwrap_or(false);

        // Extend TTL on read (only if the key exists)
        if env.storage().persistent().has(&paused_key) {
            ttl::extend_config_ttl(&env, &paused_key);
        }

        is_paused
    }

    pub fn get_flexi_rate(env: Env) -> i128 {
        rates::get_flexi_rate(&env)
    }

    pub fn get_goal_rate(env: Env) -> i128 {
        rates::get_goal_rate(&env)
    }

    pub fn get_group_rate(env: Env) -> i128 {
        rates::get_group_rate(&env)
    }

    pub fn get_lock_rate(env: Env, duration_days: u64) -> Result<i128, SavingsError> {
        rates::get_lock_rate(&env, duration_days)
    }

    pub fn get_early_break_fee_bps(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::EarlyBreakFeeBps)
            .unwrap_or(0)
    }

    pub fn get_fee_recipient(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::FeeRecipient)
    }

    pub fn get_protocol_fee_bps(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::PlatformFee)
            .unwrap_or(0)
    }

    pub fn get_protocol_fee_balance(env: Env, recipient: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::TotalBalance(recipient))
            .unwrap_or(0)
    }

    // ========== Rewards Functions ==========

    pub fn init_rewards_config(
        env: Env,
        admin: Address,
        points_per_token: u32,
        streak_bonus_bps: u32,
        long_lock_bonus_bps: u32,
        goal_completion_bonus: u32,
        enabled: bool,
        min_deposit_for_rewards: i128,
        action_cooldown_seconds: u64,
        max_daily_points: u128,
        max_streak_multiplier: u32,
    ) -> Result<(), SavingsError> {
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(SavingsError::Unauthorized)?;
        stored_admin.require_auth();

        if admin != stored_admin {
            return Err(SavingsError::Unauthorized);
        }

        let config = rewards::storage_types::RewardsConfig {
            points_per_token,
            streak_bonus_bps,
            long_lock_bonus_bps,
            goal_completion_bonus,
            enabled,
            min_deposit_for_rewards,
            action_cooldown_seconds,
            max_daily_points,
            max_streak_multiplier,
        };

        rewards::config::initialize_rewards_config(&env, config)
    }

    pub fn initialize_rewards_config(
        env: Env,
        config: rewards::storage_types::RewardsConfig,
    ) -> Result<(), SavingsError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(SavingsError::Unauthorized)?;
        admin.require_auth();
        rewards::config::initialize_rewards_config(&env, config)
    }

    pub fn update_rewards_config(
        env: Env,
        admin: Address,
        config: rewards::storage_types::RewardsConfig,
    ) -> Result<(), SavingsError> {
        rewards::config::update_rewards_config(&env, admin, config)
    }

    pub fn get_rewards_config(
        env: Env,
    ) -> Result<rewards::storage_types::RewardsConfig, SavingsError> {
        rewards::config::get_rewards_config(&env)
    }

    pub fn get_user_rewards(env: Env, user: Address) -> rewards::storage_types::UserRewards {
        rewards::storage::get_user_rewards(&env, user)
    }

    pub fn update_streak(env: Env, user: Address) -> Result<u32, SavingsError> {
        user.require_auth();
        rewards::storage::update_streak(&env, user)
    }

    // ========== Ranking Functions ==========

    /// Gets the top N users by reward points
    /// Read-only - no state mutation
    pub fn get_top_users(env: Env, limit: u32) -> Vec<(Address, u128)> {
        rewards::ranking::get_top_users(&env, limit)
    }

    /// Gets the rank of a specific user (1-indexed)
    /// Returns 0 if user has no points or is not ranked
    /// Read-only - no state mutation
    pub fn get_user_rank(env: Env, user: Address) -> u32 {
        rewards::ranking::get_user_rank(&env, &user)
    }

    /// Gets detailed ranking information for a user
    /// Returns (rank, total_points, total_users) or None
    /// Read-only - no state mutation
    pub fn get_user_ranking_details(env: Env, user: Address) -> Option<(u32, u128, u32)> {
        rewards::ranking::get_user_ranking_details(&env, &user)
    }

    // ========== Points Redemption ==========

    /// Redeem points for protocol benefits (fee discounts, boost multiplier, etc.)
    /// Validates sufficient balance and deducts points safely
    /// Emits PointsRedeemed event on success
    pub fn redeem_points(env: Env, user: Address, amount: u128) -> Result<(), SavingsError> {
        user.require_auth();
        rewards::redemption::redeem_points(&env, user, amount)
    }

    // ========== AutoSave Functions ==========

    /// Creates a new AutoSave schedule for recurring Flexi deposits
    pub fn create_autosave(
        env: Env,
        user: Address,
        amount: i128,
        interval_seconds: u64,
        start_time: u64,
    ) -> Result<u64, SavingsError> {
        ensure_not_paused(&env)?;
        autosave::create_autosave(&env, user, amount, interval_seconds, start_time)
    }

    /// Executes an AutoSave schedule if it's due
    pub fn execute_autosave(env: Env, schedule_id: u64) -> Result<(), SavingsError> {
        ensure_not_paused(&env)?;
        autosave::execute_autosave(&env, schedule_id)
    }

    /// Batch-executes multiple due AutoSave schedules in a single call.
    /// Returns a Vec<bool> indicating success (true) or skip/failure (false) per schedule.
    pub fn execute_due_autosaves(env: Env, schedule_ids: Vec<u64>) -> Vec<bool> {
        autosave::execute_due_autosaves(&env, schedule_ids)
    }

    /// Cancels an AutoSave schedule
    pub fn cancel_autosave(env: Env, user: Address, schedule_id: u64) -> Result<(), SavingsError> {
        ensure_not_paused(&env)?;
        autosave::cancel_autosave(&env, user, schedule_id)
    }

    /// Gets an AutoSave schedule by ID
    pub fn get_autosave(env: Env, schedule_id: u64) -> Option<AutoSave> {
        autosave::get_autosave(&env, schedule_id)
    }

    /// Gets all AutoSave schedule IDs for a user
    pub fn get_user_autosaves(env: Env, user: Address) -> Vec<u64> {
        autosave::get_user_autosaves(&env, &user)
    }

    // ========== Config Functions ==========

    /// Initializes the protocol configuration. Can only be called once.
    pub fn initialize_config(
        env: Env,
        admin: Address,
        treasury: Address,
        protocol_fee_bps: u32,
    ) -> Result<(), SavingsError> {
        config::initialize_config(&env, admin, treasury, protocol_fee_bps)
    }

    /// Returns the current global configuration
    pub fn get_config(env: Env) -> Result<Config, SavingsError> {
        config::get_config(&env)
    }

    /// Updates the treasury address (admin only)
    pub fn set_treasury(
        env: Env,
        admin: Address,
        new_treasury: Address,
    ) -> Result<(), SavingsError> {
        config::set_treasury(&env, admin, new_treasury)
    }

    /// Updates the protocol fee in basis points (admin only)
    pub fn set_protocol_fee(
        env: Env,
        admin: Address,
        new_fee_bps: u32,
    ) -> Result<(), SavingsError> {
        config::set_protocol_fee(&env, admin, new_fee_bps)
    }

    /// Pauses the contract via config module (admin only)
    pub fn pause_contract(env: Env, admin: Address) -> Result<(), SavingsError> {
        config::pause_contract(&env, admin)
    }

    /// Unpauses the contract via config module (admin only)
    pub fn unpause_contract(env: Env, admin: Address) -> Result<(), SavingsError> {
        config::unpause_contract(&env, admin)
    }

    pub fn upgrade(env: Env, admin: Address, new_wasm_hash: BytesN<32>) {
        upgrade::upgrade_contract(&env, admin, new_wasm_hash);
    }

    pub fn version(env: Env) -> u32 {
        upgrade::get_version(&env)
    }

    // ========== Governance Functions ==========

    /// Initializes voting configuration (admin only)
    pub fn init_voting_config(
        env: Env,
        admin: Address,
        quorum: u32,
        voting_period: u64,
        timelock_duration: u64,
        min_proposal_weight: u128,
        max_voting_power_per_user: u128,
    ) -> Result<(), SavingsError> {
        let config = governance::VotingConfig {
            quorum,
            voting_period,
            timelock_duration,
            min_proposal_weight,
            max_voting_power_per_user,
        };
        governance::init_voting_config(&env, admin, config)
    }

    /// Gets the voting configuration
    pub fn get_voting_config(env: Env) -> Result<governance::VotingConfig, SavingsError> {
        governance::get_voting_config(&env)
    }

    /// Creates a new governance proposal
    pub fn create_proposal(
        env: Env,
        creator: Address,
        description: String,
    ) -> Result<u64, SavingsError> {
        governance::create_proposal(&env, creator, description)
    }

    /// Creates a governance proposal with an action
    pub fn create_action_proposal(
        env: Env,
        creator: Address,
        description: String,
        action: governance::ProposalAction,
    ) -> Result<u64, SavingsError> {
        governance::create_action_proposal(&env, creator, description, action)
    }

    /// Gets a proposal by ID
    pub fn get_proposal(env: Env, proposal_id: u64) -> Option<governance::Proposal> {
        governance::get_proposal(&env, proposal_id)
    }

    /// Gets an action proposal by ID
    pub fn get_action_proposal(env: Env, proposal_id: u64) -> Option<governance::ActionProposal> {
        governance::get_action_proposal(&env, proposal_id)
    }

    /// Lists all proposal IDs
    pub fn list_proposals(env: Env) -> Vec<u64> {
        governance::list_proposals(&env)
    }

    /// Gets the voting power for a user based on their lifetime deposited funds
    pub fn get_voting_power(env: Env, user: Address) -> u128 {
        governance::get_voting_power(&env, &user)
    }

    /// Casts a weighted vote on a proposal
    pub fn vote(
        env: Env,
        proposal_id: u64,
        vote_type: u32,
        voter: Address,
    ) -> Result<(), SavingsError> {
        governance::vote(&env, proposal_id, vote_type, voter)
    }

    /// Checks if a user has voted on a proposal
    pub fn has_voted(env: Env, proposal_id: u64, voter: Address) -> bool {
        governance::has_voted(&env, proposal_id, &voter)
    }

    /// Queues a proposal for execution after timelock
    pub fn queue_proposal(env: Env, proposal_id: u64) -> Result<(), SavingsError> {
        governance::queue_proposal(&env, proposal_id)
    }

    /// Executes a queued proposal after timelock period
    pub fn execute_proposal(env: Env, proposal_id: u64) -> Result<(), SavingsError> {
        governance::execute_proposal(&env, proposal_id)
    }

    /// Activates governance (admin only, one-time)
    pub fn activate_governance(env: Env, admin: Address) -> Result<(), SavingsError> {
        governance::activate_governance(&env, admin)
    }

    /// Checks if governance is active
    pub fn is_governance_active(env: Env) -> bool {
        governance::is_governance_active(&env)
    }
}

#[cfg(test)]
mod admin_tests;
#[cfg(test)]
mod config_tests;
#[cfg(test)]
mod execution_tests;
#[cfg(test)]
mod governance_tests;
#[cfg(test)]
mod rates_test;
#[cfg(test)]
mod test;
#[cfg(test)]
mod transition_tests;
#[cfg(test)]
mod ttl_tests;
#[cfg(test)]
mod voting_tests;
