// New/Correct
use crate::errors::SavingsError;
use crate::storage_types::{DataKey, User};
use soroban_sdk::{Address, Env};

/// Handles depositing funds into the Flexi Save pool.
pub fn flexi_deposit(env: Env, user: Address, amount: i128) -> Result<(), SavingsError> {
    // 1. Verify the caller is the user
    user.require_auth();

    // 2. Validate the amount
    if amount <= 0 {
        return Err(SavingsError::InvalidAmount);
    }

    // 3. Update the specific Flexi balance
    let flexi_key = DataKey::FlexiBalance(user.clone());
    let current_flexi_balance = env.storage().persistent().get(&flexi_key).unwrap_or(0i128);

    let new_flexi_balance = current_flexi_balance + amount;
    env.storage()
        .persistent()
        .set(&flexi_key, &new_flexi_balance);

    // 4. Sync with the main User struct (Total Balance)
    // This ensures client.get_user() shows the increased balance in tests
    let user_key = DataKey::User(user.clone());
    if let Some(mut user_data) = env.storage().persistent().get::<DataKey, User>(&user_key) {
        user_data.total_balance += amount;
        env.storage().persistent().set(&user_key, &user_data);
    } else {
        // Optional: If user doesn't exist in User storage yet,
        // you might want to initialize them here or return an error
        return Err(SavingsError::UserNotFound);
    }

    Ok(())
}

/// Handles withdrawing funds from the Flexi Save pool.
pub fn flexi_withdraw(env: Env, user: Address, amount: i128) -> Result<(), SavingsError> {
    // 1. Verify the caller is the user
    user.require_auth();

    // 2. Validate the amount
    if amount <= 0 {
        return Err(SavingsError::InvalidAmount);
    }

    // 3. Check and update the specific Flexi balance
    let flexi_key = DataKey::FlexiBalance(user.clone());
    let current_flexi_balance = env.storage().persistent().get(&flexi_key).unwrap_or(0i128);

    if current_flexi_balance < amount {
        return Err(SavingsError::InsufficientBalance);
    }

    let new_flexi_balance = current_flexi_balance - amount;
    env.storage()
        .persistent()
        .set(&flexi_key, &new_flexi_balance);

    // 4. Sync with the main User struct (Total Balance)
    // This is necessary so that client.get_user() reflects the withdrawal
    let user_key = DataKey::User(user.clone());
    if let Some(mut user_data) = env.storage().persistent().get::<DataKey, User>(&user_key) {
        user_data.total_balance -= amount;
        env.storage().persistent().set(&user_key, &user_data);
    }

    Ok(())
}
/// Returns the user's Flexi Save balance.
/// This is a read-only (view) function.
pub fn get_flexi_balance(env: &Env, user: Address) -> Result<i128, SavingsError> {
    // 1. Ensure user exists
    let user_key = DataKey::User(user.clone());
    let _user: User = env
        .storage()
        .persistent()
        .get(&user_key)
        .ok_or(SavingsError::UserNotFound)?;

    // 2. Read flexi balance (default to 0)
    let flexi_key = DataKey::FlexiBalance(user);
    let balance = env.storage().persistent().get(&flexi_key).unwrap_or(0i128);

    Ok(balance)
}

/// Returns true if the user has a non-zero Flexi Save balance.
/// This function does not mutate storage.
pub fn has_flexi_balance(env: &Env, user: Address) -> bool {
    let flexi_key = DataKey::FlexiBalance(user);
    let balance = env.storage().persistent().get(&flexi_key).unwrap_or(0i128);

    balance > 0
}
