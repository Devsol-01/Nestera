//! Event definitions and helpers for the rewards module.
use soroban_sdk::{contracttype, symbol_short, Address, Env, Symbol};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PointsAwarded {
    pub user: Address,
    pub amount: u128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BonusAwarded {
    pub user: Address,
    pub amount: u128,
    pub bonus_type: Symbol, // e.g., "streak", "lock", "goal"
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PointsRedeemed {
    pub user: Address,
    pub amount: u128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreakUpdated {
    pub user: Address,
    pub streak: u32,
}

/// Emits a PointsAwarded event.
pub fn emit_points_awarded(env: &Env, user: Address, amount: u128) {
    let event = PointsAwarded {
        user: user.clone(),
        amount,
    };
    env.events().publish(
        (symbol_short!("rewards"), symbol_short!("awarded"), user),
        event,
    );
}

/// Emits a BonusAwarded event.
pub fn emit_bonus_awarded(env: &Env, user: Address, amount: u128, bonus_type: Symbol) {
    let event = BonusAwarded {
        user: user.clone(),
        amount,
        bonus_type,
    };
    env.events().publish(
        (symbol_short!("rewards"), symbol_short!("bonus"), user),
        event,
    );
}

/// Emits a PointsRedeemed event.
pub fn emit_points_redeemed(env: &Env, user: Address, amount: u128) {
    let event = PointsRedeemed {
        user: user.clone(),
        amount,
    };
    env.events().publish(
        (symbol_short!("rewards"), symbol_short!("redeem"), user),
        event,
    );
}

/// Emits a StreakUpdated event.
pub fn emit_streak_updated(env: &Env, user: Address, streak: u32) {
    let event = StreakUpdated {
        user: user.clone(),
        streak,
    };
    env.events().publish(
        (symbol_short!("rewards"), symbol_short!("streak"), user),
        event,
    );
}
