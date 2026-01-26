#![no_std]
#![allow(non_snake_case)]
mod flexi;
mod goal;
mod group;
mod lock;
mod storage_types;
mod users;
mod views;

pub use crate::errors::SavingsError;
pub use crate::storage_types::User;
use soroban_sdk::{
    contract, contractimpl, panic_with_error, symbol_short, xdr::ToXdr, Address, Bytes, BytesN,
    Env, String, Symbol, Vec,
};
pub use storage_types::{
    DataKey, GoalSave, GoalSave, GroupSave, GroupSave, LockSave, LockSave, MintPayload, PlanType,
    SavingsPlan,
};

/// Custom error codes for the contract
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ContractError {
    /// Contract has already been initialized
    AlreadyInitialized = 1,
    /// Contract has not been initialized
    NotInitialized = 2,
    /// Invalid signature provided
    InvalidSignature = 3,
    /// Signature has expired
    SignatureExpired = 4,
}

impl From<ContractError> for soroban_sdk::Error {
    fn from(e: ContractError) -> Self {
        soroban_sdk::Error::from_contract_error(e as u32)
    }
}

mod errors;
pub use errors::*;

#[contract]
pub struct NesteraContract;

#[contractimpl]
impl NesteraContract {
    /// Initializes the contract with the admin's Ed25519 public key.
    /// This function can only be called once.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `admin_public_key` - The 32-byte Ed25519 public key of the admin
    ///
    /// # Panics
    /// Panics if the contract has already been initialized.
    #[allow(deprecated)]
    pub fn initialize(env: Env, admin_public_key: BytesN<32>) {
        // Check if already initialized
        if env.storage().instance().has(&DataKey::Initialized) {
            panic_with_error!(&env, ContractError::AlreadyInitialized);
        }

        // Store the admin public key
        env.storage()
            .instance()
            .set(&DataKey::AdminPublicKey, &admin_public_key);

        // Mark as initialized
        env.storage().instance().set(&DataKey::Initialized, &true);

        // Emit initialization event
        env.events()
            .publish((symbol_short!("init"),), admin_public_key);
    }

    /// Verifies that a signature is valid for the given payload.
    /// This is the core security checkpoint that validates admin approval.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `payload` - The mint payload that was signed
    /// * `signature` - The 64-byte Ed25519 signature from the admin
    ///
    /// # Panics
    /// * Panics if the contract is not initialized
    /// * Panics if the signature is invalid
    /// * Panics if the signature has expired
    pub fn verify_signature(env: Env, payload: MintPayload, signature: BytesN<64>) -> bool {
        // Ensure contract is initialized
        if !env.storage().instance().has(&DataKey::Initialized) {
            panic_with_error!(&env, ContractError::NotInitialized);
        }

        // Check signature expiry using ledger timestamp
        let current_timestamp = env.ledger().timestamp();
        let expiry_time = payload.timestamp + payload.expiry_duration;

        if current_timestamp > expiry_time {
            panic_with_error!(&env, ContractError::SignatureExpired);
        }

        // Fetch admin public key from storage
        let admin_public_key: BytesN<32> = env
            .storage()
            .instance()
            .get(&DataKey::AdminPublicKey)
            .expect("Admin public key not found");

        // Serialize the payload to XDR bytes for verification
        // This ensures consistent serialization between off-chain signing and on-chain verification
        let payload_bytes: Bytes = payload.to_xdr(&env);

        // Verify the Ed25519 signature
        // This will panic if the signature is invalid
        env.crypto()
            .ed25519_verify(&admin_public_key, &payload_bytes, &signature);

        true
    }

    /// Mints tokens for a user after verifying the admin's signature.
    /// Users call this function themselves, paying the gas fees.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `payload` - The mint payload containing user address and amount
    /// * `signature` - The 64-byte Ed25519 signature from the admin
    ///
    /// # Returns
    /// The amount of tokens minted
    ///
    /// # Panics
    /// * Panics if signature verification fails
    /// * Panics if the signature has expired
    #[allow(deprecated)]
    pub fn mint(env: Env, payload: MintPayload, signature: BytesN<64>) -> i128 {
        // Verify the signature first - this is the security checkpoint
        Self::verify_signature(env.clone(), payload.clone(), signature);

        // At this point, the signature is valid and not expired
        // The user is authorized to mint the specified amount

        let amount = payload.amount;
        let user = payload.user.clone();

        // Emit mint event
        env.events()
            .publish((symbol_short!("mint"), user.clone()), amount);

        // TODO: Implement actual token minting logic here
        // This would typically interact with a token contract
        // For now, we return the amount that would be minted

        amount
    }

    /// Returns the stored admin public key.
    /// Useful for off-chain verification and debugging.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    ///
    /// # Returns
    /// The 32-byte admin public key
    ///
    /// # Panics
    /// Panics if the contract is not initialized.
    pub fn get_admin_public_key(env: Env) -> BytesN<32> {
        if !env.storage().instance().has(&DataKey::Initialized) {
            panic_with_error!(&env, ContractError::NotInitialized);
        }

        env.storage()
            .instance()
            .get(&DataKey::AdminPublicKey)
            .expect("Admin public key not found")
    }

    /// Checks if the contract has been initialized.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    ///
    /// # Returns
    /// `true` if initialized, `false` otherwise
    pub fn is_initialized(env: Env) -> bool {
        env.storage().instance().has(&DataKey::Initialized)
    }

    #[allow(deprecated)]
    pub fn create_savings_plan(
        env: Env,
        user: Address,
        plan_type: PlanType,
        initial_deposit: i128,
    ) -> u64 {
        if !Self::is_initialized(env.clone()) {
            panic_with_error!(&env, ContractError::NotInitialized);
        }

        let mut user_data = Self::get_user(env.clone(), user.clone())
            .ok()
            .unwrap_or(User {
                total_balance: 0,
                savings_count: 0,
            });

        user_data.savings_count += 1;
        user_data.total_balance += initial_deposit;

        let plan_id = user_data.savings_count as u64;

        let new_plan = SavingsPlan {
            plan_id,
            plan_type: plan_type.clone(),
            balance: initial_deposit,
            start_time: env.ledger().timestamp(),
            last_deposit: env.ledger().timestamp(),
            last_withdraw: 0,
            interest_rate: 500, // Default 5%
            is_completed: false,
            is_withdrawn: false,
        };

        // Store user data
        env.storage()
            .persistent()
            .set(&DataKey::User(user.clone()), &user_data);

        // Store plan data
        env.storage()
            .persistent()
            .set(&DataKey::SavingsPlan(user.clone(), plan_id), &new_plan);

        // Emit event
        env.events().publish(
            (Symbol::new(&env, "create_plan"), user, plan_id),
            initial_deposit,
        );

        plan_id
    }

    pub fn get_savings_plan(env: Env, user: Address, plan_id: u64) -> Option<SavingsPlan> {
        env.storage()
            .persistent()
            .get(&DataKey::SavingsPlan(user, plan_id))
    }

    pub fn get_user_savings_plans(env: Env, user: Address) -> Vec<SavingsPlan> {
        let user_data = Self::get_user(env.clone(), user.clone()).ok();
        let mut plans = Vec::new(&env);

        if let Some(data) = user_data {
            for i in 1..=data.savings_count {
                let plan_id = i as u64;
                if let Some(plan) = Self::get_savings_plan(env.clone(), user.clone(), plan_id) {
                    plans.push_back(plan);
                }
            }
        }
        plans
    }

    /// Initialize a new user in the savings contract
    pub fn initialize_user(env: Env, user: Address) -> Result<(), SavingsError> {
        users::initialize_user(&env, user)
    }

    /// Check if a user exists in the contract
    pub fn user_exists(env: Env, user: Address) -> bool {
        users::user_exists(&env, &user)
    }

    /// Get user data from the contract
    pub fn get_user(env: Env, user: Address) -> Result<User, SavingsError> {
        users::get_user(&env, &user)
    }

    /// Public entry point to deposit into Flexi Save
    pub fn deposit_flexi(env: Env, user: Address, amount: i128) -> Result<(), SavingsError> {
        flexi::flexi_deposit(env, user, amount)
    }

    /// Public entry point to withdraw from Flexi Save
    pub fn withdraw_flexi(env: Env, user: Address, amount: i128) -> Result<(), SavingsError> {
        flexi::flexi_withdraw(env, user, amount)
    }

    // =======================================================================
    // View Functions
    // =======================================================================

    // Lock Save Views
    pub fn get_user_ongoing_lock_saves(
        env: Env,
        user: Address,
    ) -> Result<Vec<LockSave>, SavingsError> {
        views::get_user_ongoing_lock_saves(&env, user)
    }

    pub fn get_user_matured_lock_saves(
        env: Env,
        user: Address,
    ) -> Result<Vec<LockSave>, SavingsError> {
        views::get_user_matured_lock_saves(&env, user)
    }

    pub fn get_lock_save(env: Env, user: Address, lock_id: u64) -> Result<LockSave, SavingsError> {
        views::get_lock_save(&env, user, lock_id)
    }

    // Goal Save Views
    pub fn get_user_live_goal_saves(
        env: Env,
        user: Address,
    ) -> Result<Vec<GoalSave>, SavingsError> {
        views::get_user_live_goal_saves(&env, user)
    }

    pub fn get_user_completed_goal_saves(
        env: Env,
        user: Address,
    ) -> Result<Vec<GoalSave>, SavingsError> {
        views::get_user_completed_goal_saves(&env, user)
    }

    pub fn get_goal_save(env: Env, user: Address, goal_id: u64) -> Result<GoalSave, SavingsError> {
        views::get_goal_save(&env, user, goal_id)
    }

    // Group Save Views
    pub fn get_user_live_group_saves(
        env: Env,
        user: Address,
    ) -> Result<Vec<GroupSave>, SavingsError> {
        views::get_user_live_group_saves(&env, user)
    }

    pub fn get_user_completed_group_saves(
        env: Env,
        user: Address,
    ) -> Result<Vec<GroupSave>, SavingsError> {
        views::get_user_completed_group_saves(&env, user)
    }

    pub fn get_group_save(
        env: Env,
        user: Address,
        group_id: u64,
    ) -> Result<GroupSave, SavingsError> {
        views::get_group_save(&env, user, group_id)
    }

    // Member Views
    pub fn is_group_member(env: Env, group_id: u64, user: Address) -> Result<bool, SavingsError> {
        views::is_group_member(&env, group_id, user)
    }

    pub fn get_group_member_contribution(
        env: Env,
        group_id: u64,
        user: Address,
    ) -> Result<i128, SavingsError> {
        views::get_group_member_contribution(&env, group_id, user)
    }

    /// VIEW FUNCTION
    pub fn get_flexi_balance(env: Env, user: Address) -> i128 {
        flexi::get_flexi_balance(&env, user).unwrap()
    }

    /// VIEW FUNCTION
    pub fn has_flexi_balance(env: Env, user: Address) -> bool {
        flexi::has_flexi_balance(&env, user)
    }

    /// Creates a new group savings plan.
    /// The creator becomes the first member of the group.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `creator` - The address of the user creating the group
    /// * `title` - Title/name of the group savings plan
    /// * `description` - Description of the group savings goal
    /// * `category` - Category of the group savings
    /// * `target_amount` - Target amount to save (must be > 0)
    /// * `contribution_type` - Type of contribution (0 = fixed, 1 = flexible, 2 = percentage)
    /// * `contribution_amount` - Contribution amount or minimum (must be > 0)
    /// * `is_public` - Whether the group is public or private
    /// * `start_time` - Unix timestamp when the group starts
    /// * `end_time` - Unix timestamp when the group ends
    ///
    /// # Returns
    /// `Ok(u64)` - The unique ID of the created group
    /// `Err(SavingsError)` - If validation fails
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

    /// VIEW FUNCTION - Retrieves a group savings plan by ID.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `group_id` - The unique ID of the group
    ///
    /// # Returns
    /// `Some(GroupSave)` if the group exists, `None` otherwise
    pub fn get_group_save(env: Env, group_id: u64) -> Option<crate::storage_types::GroupSave> {
        group::get_group_save(&env, group_id)
    }

    /// VIEW FUNCTION - Checks if a group exists.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `group_id` - The unique ID of the group
    ///
    /// # Returns
    /// `true` if the group exists, `false` otherwise
    pub fn group_exists(env: Env, group_id: u64) -> bool {
        group::group_exists(&env, group_id)
    }

    /// VIEW FUNCTION - Gets all groups that a user participates in.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `user` - The user address
    ///
    /// # Returns
    /// A vector of group IDs the user is involved in
    pub fn get_user_groups(env: Env, user: Address) -> Vec<u64> {
        group::get_user_groups(&env, &user)
    }

    /// Allows a user to join a public group savings plan.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `user` - The address of the user joining the group
    /// * `group_id` - The ID of the group to join
    ///
    /// # Returns
    /// `Ok(())` on success, panics on error
    pub fn join_group_save(env: Env, user: Address, group_id: u64) -> Result<(), SavingsError> {
        group::join_group_save(&env, user, group_id)
    }

    /// Allows a group member to contribute funds to the group savings plan.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `user` - The address of the user contributing
    /// * `group_id` - The ID of the group
    /// * `amount` - The amount to contribute (must be > 0)
    ///
    /// # Returns
    /// `Ok(())` on success, panics on error
    pub fn contribute_to_group_save(
        env: Env,
        user: Address,
        group_id: u64,
        amount: i128,
    ) -> Result<(), SavingsError> {
        group::contribute_to_group_save(&env, user, group_id, amount)
    }

    /// VIEW FUNCTION - Gets a member's contribution to a group.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `group_id` - The group ID
    /// * `user` - The user address
    ///
    /// # Returns
    /// The member's total contribution amount
    pub fn get_member_contribution(env: Env, group_id: u64, user: Address) -> i128 {
        group::get_member_contribution(&env, group_id, &user)
    }

    /// VIEW FUNCTION - Gets all members of a group.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `group_id` - The group ID
    ///
    /// # Returns
    /// A vector of member addresses
    pub fn get_group_members(env: Env, group_id: u64) -> Vec<Address> {
        group::get_group_members(&env, group_id)
    }

    // ========== Lock Save Functions ==========

    /// Creates a new Lock Save plan for a user
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `user` - The address of the user creating the lock save
    /// * `amount` - The amount to lock (must be positive)
    /// * `duration` - The lock duration in seconds (must be positive)
    ///
    /// # Returns
    /// The unique lock save ID
    ///
    /// # Panics
    /// Panics on validation errors or if user doesn't exist
    pub fn create_lock_save(env: Env, user: Address, amount: i128, duration: u64) -> u64 {
        lock::create_lock_save(&env, user, amount, duration)
            .unwrap_or_else(|e| panic_with_error!(&env, e))
    }

    /// Checks if a lock save plan has matured
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `lock_id` - The ID of the lock save to check
    ///
    /// # Returns
    /// `true` if the lock save has matured, `false` otherwise
    pub fn check_matured_lock(env: Env, lock_id: u64) -> bool {
        lock::check_matured_lock(&env, lock_id)
    }

    /// Retrieves a lock save by ID
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `lock_id` - The ID of the lock save to retrieve
    ///
    /// # Returns
    /// The LockSave struct if found, panics if not found
    pub fn get_lock_save(env: Env, lock_id: u64) -> LockSave {
        lock::get_lock_save(&env, lock_id)
            .unwrap_or_else(|| panic_with_error!(&env, SavingsError::PlanNotFound))
    }

    /// Retrieves all lock save IDs for a user
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `user` - The user's address
    ///
    /// # Returns
    /// Vector of lock save IDs owned by the user
    pub fn get_user_lock_saves(env: Env, user: Address) -> Vec<u64> {
        lock::get_user_lock_saves(&env, &user)
    }

    /// Withdraws from a matured lock save plan
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `user` - The user attempting to withdraw
    /// * `lock_id` - The ID of the lock save to withdraw from
    ///
    /// # Returns
    /// The amount withdrawn (including interest)
    ///
    /// # Panics
    /// Panics if withdrawal conditions are not met
    pub fn withdraw_lock_save(env: Env, user: Address, lock_id: u64) -> i128 {
        lock::withdraw_lock_save(&env, user, lock_id).unwrap_or_else(|e| panic_with_error!(&env, e))
    }

    // ========== Goal Save Functions ==========

    pub fn create_goal_save(
        env: Env,
        user: Address,
        goal_name: Symbol,
        target_amount: i128,
        initial_deposit: i128,
    ) -> u64 {
        goal::create_goal_save(&env, user, goal_name, target_amount, initial_deposit)
            .unwrap_or_else(|e| panic_with_error!(&env, e))
    }

    pub fn deposit_to_goal_save(env: Env, user: Address, goal_id: u64, amount: i128) {
        goal::deposit_to_goal_save(&env, user, goal_id, amount)
            .unwrap_or_else(|e| panic_with_error!(&env, e))
    }

    pub fn withdraw_completed_goal_save(env: Env, user: Address, goal_id: u64) -> i128 {
        goal::withdraw_completed_goal_save(&env, user, goal_id)
            .unwrap_or_else(|e| panic_with_error!(&env, e))
    }

    pub fn break_goal_save(env: Env, user: Address, goal_id: u64) {
        goal::break_goal_save(&env, user, goal_id).unwrap_or_else(|e| panic_with_error!(&env, e))
    }

    pub fn get_goal_save(env: Env, goal_id: u64) -> GoalSave {
        goal::get_goal_save(&env, goal_id)
            .unwrap_or_else(|| panic_with_error!(&env, SavingsError::PlanNotFound))
    }

    pub fn get_user_goal_saves(env: Env, user: Address) -> Vec<u64> {
        goal::get_user_goal_saves(&env, &user)
    }
}

#[cfg(test)]
mod test;
