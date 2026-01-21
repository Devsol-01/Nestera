#![cfg(test)]
extern crate std;

use super::*;
use soroban_sdk::{testutils::Address as _, Address, Env};

#[test]
fn test_initialize_sets_admin() {
    let env = Env::default();
    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    
    // Mock authentication for the admin
    env.mock_all_auths();
    
    // Initialize the contract with admin
    client.initialize(&admin);
    
    // Verify admin was set correctly
    let stored_admin = client.get_admin();
    assert_eq!(stored_admin, admin);
}

#[test]
#[should_panic(expected = "Admin already initialized")]
fn test_initialize_twice_fails() {
    let env = Env::default();
    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    
    // Mock authentication
    env.mock_all_auths();
    
    // Initialize the contract - should succeed
    client.initialize(&admin);
    
    // Try to initialize again - should panic
    client.initialize(&admin);
}

#[test]
fn test_update_admin_by_current_admin_succeeds() {
    let env = Env::default();
    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    
    // Mock authentication
    env.mock_all_auths();
    
    // Initialize with first admin
    client.initialize(&admin);
    
    // Update to new admin
    client.update_admin(&new_admin);
    
    // Verify admin was updated
    let stored_admin = client.get_admin();
    assert_eq!(stored_admin, new_admin);
}

#[test]
fn test_update_admin_requires_current_admin_auth() {
    let env = Env::default();
    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    
    // Initialize with admin
    env.mock_all_auths();
    client.initialize(&admin);
    
    // Clear previous auths and test update_admin
    env.mock_all_auths_allowing_non_root_auth();
    client.update_admin(&new_admin);
    
    // Verify that both admin and new_admin were required to authorize
    // We expect 2 authorizations: one from current admin, one from new admin
    assert_eq!(env.auths().len(), 2);
    
    // Verify the first auth is from the current admin
    let auth_addresses: std::vec::Vec<_> = env.auths()
        .iter()
        .map(|(addr, _)| addr.clone())
        .collect();
    
    assert!(auth_addresses.contains(&admin));
    assert!(auth_addresses.contains(&new_admin));
}

#[test]
#[should_panic(expected = "Admin not initialized")]
fn test_get_admin_fails_when_not_initialized() {
    let env = Env::default();
    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);
    
    // Try to get admin without initializing - should panic
    client.get_admin();
}

#[test]
#[should_panic(expected = "Admin not initialized")]
fn test_update_admin_fails_when_not_initialized() {
    let env = Env::default();
    let contract_id = env.register(NesteraContract, ());
    let client = NesteraContractClient::new(&env, &contract_id);
    
    let new_admin = Address::generate(&env);
    
    // Mock authentication
    env.mock_all_auths();
    
    // Try to update admin without initializing - should panic
    client.update_admin(&new_admin);
}


