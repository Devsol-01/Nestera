#![no_std]
#![allow(non_snake_case)]
use soroban_sdk::{contract, contractimpl, Address, Env};

pub mod storage_types;
pub mod users;

pub use storage_types::*;

mod errors;
pub use errors::*;

#[contract]
pub struct NesteraContract;

#[contractimpl]
impl NesteraContract {
    /// Initialize the contract with an admin
    pub fn initialize(e: Env, admin: Address) {
        if e.storage().instance().has(&DataKey::Admin) {
            panic!("Admin already initialized");
        }

        admin.require_auth();

        e.storage().instance().set(&DataKey::Admin, &admin);
    }

    /// Update the contract admin
    pub fn update_admin(e: Env, new_admin: Address) {
        let admin = Self::get_admin(&e);

        admin.require_auth();

        new_admin.require_auth();

        e.storage().instance().set(&DataKey::Admin, &new_admin);
    }

    /// Get the current admin
    pub fn get_admin(e: &Env) -> Address {
        e.storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("Admin not initialized")
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
}

mod test;
