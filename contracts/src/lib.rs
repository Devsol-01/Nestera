#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

mod storage_types;
use storage_types::DataKey;

#[contract]
pub struct NesteraContract;

#[contractimpl]
impl NesteraContract {
    pub fn initialize(e: Env, admin: Address) {
        if e.storage().instance().has(&DataKey::Admin) {
            panic!("Admin already initialized");
        }

        admin.require_auth();

        e.storage().instance().set(&DataKey::Admin, &admin);
    }

    pub fn update_admin(e: Env, new_admin: Address) {
        let admin = Self::get_admin(&e);

        admin.require_auth();

        new_admin.require_auth();

        e.storage().instance().set(&DataKey::Admin, &new_admin);
    }

    pub fn get_admin(e: &Env) -> Address {
        e.storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("Admin not initialized")
    }
}

mod test;
