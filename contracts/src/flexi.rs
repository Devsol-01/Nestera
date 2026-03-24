// New/Correct
use crate::calculate_fee;
use crate::ensure_not_paused;
use crate::errors::SavingsError;
use crate::invariants;
use crate::rewards;
use crate::storage_types::{DataKey, User};
use crate::ttl;
use soroban_sdk::{symbol_short, Address, Env};

/// Handles depositing funds into the Flexi Save pool.
pub fn flexi_deposit(env: Env, user: Address, amount: i128) -> Result<(), SavingsError> {
    ensure_not_paused(&env)?;

    // 1. Verify the caller is the user
    user.require_auth();

    // 2. Validate the amount
    if amount <= 0 {
        return Err(SavingsError::InvalidAmount);
    }

    // 3. Calculate protocol fee
    let fee_bps: u32 = env
        .storage()
        .instance()
        .get(&DataKey::DepositFeeBps)
        .unwrap_or(0);

    let fee_amount = calculate_fee(amount, fee_bps)?;
    let net_amount = amount
        .checked_sub(fee_amount)
        .ok_or(SavingsError::Underflow)?;

    // 4. Update the specific Flexi balance with net amount
    let flexi_key = DataKey::FlexiBalance(user.clone());
    let current_flexi_balance = env.storage().persistent().get(&flexi_key).unwrap_or(0i128);

    let new_flexi_balance = current_flexi_balance
        .checked_add(net_amount)
        .ok_or(SavingsError::Overflow)?;
    env.storage()
        .persistent()
        .set(&flexi_key, &new_flexi_balance);

    // 5. Sync with the main User struct (Total Balance)
    let user_key = DataKey::User(user.clone());
    if let Some(mut user_data) = env.storage().persistent().get::<DataKey, User>(&user_key) {
        user_data.total_balance = user_data
            .total_balance
            .checked_add(net_amount)
            .ok_or(SavingsError::Overflow)?;
        env.storage().persistent().set(&user_key, &user_data);
    } else {
        return Err(SavingsError::UserNotFound);
    }

    // Extend TTL on user interaction
    ttl::extend_user_ttl(&env, &user);

    // 6. Award deposit points (streak, rewards)
    rewards::storage::award_deposit_points(&env, user.clone(), amount)?;

    // 7. Transfer fee to treasury if fee > 0
    if fee_amount > 0 {
        if let Some(fee_recipient) = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::FeeRecipient)
        {
            let fee_key = DataKey::TotalBalance(fee_recipient.clone());
            let current_fee_balance = env
                .storage()
                .persistent()
                .get::<DataKey, i128>(&fee_key)
                .unwrap_or(0i128);
            let new_fee_balance = current_fee_balance
                .checked_add(fee_amount)
                .ok_or(SavingsError::Overflow)?;
            env.storage().persistent().set(&fee_key, &new_fee_balance);
            env.events()
                .publish((symbol_short!("dep_fee"), fee_recipient), fee_amount);
        }
        // Record fee in treasury struct
        crate::treasury::record_fee(&env, fee_amount, soroban_sdk::Symbol::new(&env, "deposit"));
    }

    Ok(())
}

/// Handles withdrawing funds from the Flexi Save pool.
pub fn flexi_withdraw(env: Env, user: Address, amount: i128) -> Result<(), SavingsError> {
    ensure_not_paused(&env)?;

    // 1. Verify the caller is the user
    user.require_auth();

    // 2. Validate the amount
    if amount <= 0 {
        return Err(SavingsError::InvalidAmount);
    }

    // 1. Fetch the balance first
    let current_balance = get_flexi_balance(&env, user.clone()).unwrap_or(0);

    // 2. Now the variable 'current_balance' exists in this scope
    invariants::assert_sufficient_balance(current_balance, amount)?;

    // 3. Calculate protocol fee
    let fee_bps: u32 = env
        .storage()
        .instance()
        .get(&DataKey::WithdrawalFeeBps)
        .unwrap_or(0);

    let fee_amount = calculate_fee(amount, fee_bps)?;
    let _net_amount = amount
        .checked_sub(fee_amount)
        .ok_or(SavingsError::Underflow)?;

    // 4. Check and update the specific Flexi balance
    let flexi_key = DataKey::FlexiBalance(user.clone());
    let current_flexi_balance = env.storage().persistent().get(&flexi_key).unwrap_or(0i128);

    if current_flexi_balance < amount {
        return Err(SavingsError::InsufficientBalance);
    }

    let new_flexi_balance = current_flexi_balance
        .checked_sub(amount)
        .ok_or(SavingsError::Underflow)?;
    env.storage()
        .persistent()
        .set(&flexi_key, &new_flexi_balance);

    // 5. Sync with the main User struct (Total Balance)
    let user_key = DataKey::User(user.clone());
    if let Some(mut user_data) = env.storage().persistent().get::<DataKey, User>(&user_key) {
        user_data.total_balance = user_data
            .total_balance
            .checked_sub(amount)
            .ok_or(SavingsError::Underflow)?;
        env.storage().persistent().set(&user_key, &user_data);
    }

    // Extend TTL on user interaction
    ttl::extend_user_ttl(&env, &user);

    // 6. Transfer fee to treasury if fee > 0
    if fee_amount > 0 {
        if let Some(fee_recipient) = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::FeeRecipient)
        {
            let fee_key = DataKey::TotalBalance(fee_recipient.clone());
            let current_fee_balance = env
                .storage()
                .persistent()
                .get::<DataKey, i128>(&fee_key)
                .unwrap_or(0i128);
            let new_fee_balance = current_fee_balance
                .checked_add(fee_amount)
                .ok_or(SavingsError::Overflow)?;
            env.storage().persistent().set(&fee_key, &new_fee_balance);
            env.events()
                .publish((symbol_short!("wth_fee"), fee_recipient), fee_amount);
        }
        // Record fee in treasury struct
        crate::treasury::record_fee(&env, fee_amount, soroban_sdk::Symbol::new(&env, "withdraw"));
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
    let flexi_key = DataKey::FlexiBalance(user.clone());
    let balance = env.storage().persistent().get(&flexi_key).unwrap_or(0i128);

    // Extend TTL on read
    ttl::extend_user_ttl(env, &user);

    Ok(balance)
}

/// Returns true if the user has a non-zero Flexi Save balance.
/// This function does not mutate storage.
pub fn has_flexi_balance(env: &Env, user: Address) -> bool {
    let flexi_key = DataKey::FlexiBalance(user.clone());
    let balance = env.storage().persistent().get(&flexi_key).unwrap_or(0i128);

    // Extend TTL on read
    ttl::extend_user_ttl(env, &user);

    balance > 0
}

#[cfg(test)]
mod tests {
    use crate::{NesteraContract, NesteraContractClient};
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup_admin_env() -> (Env, NesteraContractClient<'static>, Address) {
        let env = Env::default();
        let contract_id = env.register(NesteraContract, ());
        let client = NesteraContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let admin_pk = soroban_sdk::BytesN::from_array(&env, &[1u8; 32]);

        env.mock_all_auths();
        client.initialize(&admin, &admin_pk);

        (env, client, admin)
    }

    #[test]
    fn test_flexi_deposit_with_protocol_fee() {
        let (env, client, admin) = setup_admin_env();
        let user = Address::generate(&env);
        let treasury = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user);
        assert!(client.try_set_fee_recipient(&treasury).is_ok());
        assert!(client.try_set_fees(&admin, &500, &500, &500).is_ok()); // 5%

        let deposit_amount = 10_000i128;
        client.deposit_flexi(&user, &deposit_amount);

        // Net amount = 10,000 - 500 = 9,500
        assert_eq!(client.get_flexi_balance(&user), 9_500);
        assert_eq!(client.get_protocol_fee_balance(&treasury), 500);
    }

    #[test]
    fn test_flexi_deposit_zero_fee() {
        let (env, client, _admin) = setup_admin_env();
        let user = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user);

        let deposit_amount = 10_000i128;
        client.deposit_flexi(&user, &deposit_amount);

        // No fee, full amount deposited
        assert_eq!(client.get_flexi_balance(&user), 10_000);
    }

    #[test]
    fn test_flexi_withdraw_with_protocol_fee() {
        let (env, client, admin) = setup_admin_env();
        let user = Address::generate(&env);
        let treasury = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user);
        assert!(client.try_set_fee_recipient(&treasury).is_ok());
        assert!(client.try_set_fees(&admin, &250, &250, &250).is_ok()); // 2.5%

        client.deposit_flexi(&user, &10_000);
        let balance_before = client.get_flexi_balance(&user);

        client.withdraw_flexi(&user, &4_000);

        // Withdrawal: 4,000 deducted from balance
        // Fee: 4,000 * 0.025 = 100
        // Net to user: 3,900
        assert_eq!(client.get_flexi_balance(&user), balance_before - 4_000);
        assert_eq!(client.get_protocol_fee_balance(&treasury), 350); // 250 from deposit + 100 from withdrawal
    }

    #[test]
    fn test_flexi_withdraw_zero_fee() {
        let (env, client, _admin) = setup_admin_env();
        let user = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user);

        client.deposit_flexi(&user, &10_000);
        client.withdraw_flexi(&user, &3_000);

        assert_eq!(client.get_flexi_balance(&user), 7_000);
    }

    #[test]
    fn test_flexi_fee_rounds_down() {
        let (env, client, admin) = setup_admin_env();
        let user = Address::generate(&env);
        let treasury = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user);
        assert!(client.try_set_fee_recipient(&treasury).is_ok());
        assert!(client.try_set_fees(&admin, &125, &125, &125).is_ok()); // 1.25%

        client.deposit_flexi(&user, &3_333);

        // Fee = floor(3333 * 125 / 10000) = 41
        // Net = 3333 - 41 = 3292
        assert_eq!(client.get_flexi_balance(&user), 3_292);
        assert_eq!(client.get_protocol_fee_balance(&treasury), 41);
    }

    #[test]
    fn test_flexi_small_amount_edge_case() {
        let (env, client, admin) = setup_admin_env();
        let user = Address::generate(&env);
        let treasury = Address::generate(&env);

        env.mock_all_auths();
        client.initialize_user(&user);
        assert!(client.try_set_fee_recipient(&treasury).is_ok());
        assert!(client.try_set_fees(&admin, &100, &100, &100).is_ok()); // 1%

        // Small amount where fee would be < 1
        client.deposit_flexi(&user, &50);

        // Fee = floor(50 * 100 / 10000) = 0
        // Net = 50 - 0 = 50
        assert_eq!(client.get_flexi_balance(&user), 50);
        assert_eq!(client.get_protocol_fee_balance(&treasury), 0);
    }
}
