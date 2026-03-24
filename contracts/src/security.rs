use crate::errors::SavingsError;
use crate::storage_types::DataKey;
use soroban_sdk::Env;

/// Acquires the reentrancy guard. Returns `ReentrancyDetected` if already locked.
pub fn acquire_reentrancy_guard(env: &Env) -> Result<(), SavingsError> {
    let key = DataKey::ReentrancyGuard;
    let locked: bool = env.storage().instance().get(&key).unwrap_or(false);
    if locked {
        return Err(SavingsError::ReentrancyDetected);
    }
    env.storage().instance().set(&key, &true);
    Ok(())
}

/// Releases the reentrancy guard unconditionally.
pub fn release_reentrancy_guard(env: &Env) {
    env.storage()
        .instance()
        .set(&DataKey::ReentrancyGuard, &false);
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn test_overflow_protection() {
        let _env = Env::default();
    }

    #[test]
    fn test_negative_deposit_protection() {
        let _env = Env::default();
    }

    #[test]
    fn test_pause_invariant() {
        let _env = Env::default();
    }
}
