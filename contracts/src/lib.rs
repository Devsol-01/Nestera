#![no_std]
#![allow(non_snake_case)]
mod flexi;
mod group;
mod storage_types;
mod users;

pub use crate::errors::SavingsError;
pub use crate::storage_types::User;
use soroban_sdk::{
    contract, contractimpl, panic_with_error, symbol_short, xdr::ToXdr, Address, Bytes, BytesN,
    Env, Symbol, Vec,
};
pub use storage_types::{DataKey, GroupSave, MintPayload, PlanType, SavingsPlan};

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

    /// Create a new group savings plan
    pub fn create_group_save(
        env: Env,
        creator: Address,
        is_public: bool,
        target_amount: i128,
        max_members: u32,
        contribution_type: u32,
    ) -> Result<u64, SavingsError> {
        group::create_group_save(&env, creator, is_public, target_amount, max_members, contribution_type)
    }

    /// Join a public group savings plan
    pub fn join_group_save(env: Env, user: Address, group_id: u64) -> Result<(), SavingsError> {
        group::join_group_save(&env, user, group_id)
    }

    /// Contribute to a group savings plan
    pub fn contribute_to_group_save(
        env: Env,
        user: Address,
        group_id: u64,
        amount: i128,
    ) -> Result<(), SavingsError> {
        group::contribute_to_group_save(&env, user, group_id, amount)
    }

    /// Get group information
    pub fn get_group(env: Env, group_id: u64) -> Result<GroupSave, SavingsError> {
        group::get_group(&env, group_id)
    }

    /// Get a member's contribution to a group
    pub fn get_member_contribution(env: Env, group_id: u64, user: Address) -> i128 {
        group::get_member_contribution(&env, group_id, &user)
    }

    /// Check if a user is a member of a group
    pub fn is_group_member(env: Env, user: Address, group_id: u64) -> bool {
        group::is_group_member(&env, &user, group_id)
    }
}

#[cfg(test)]
mod test;
