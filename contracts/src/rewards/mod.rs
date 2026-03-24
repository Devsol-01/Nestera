pub mod config;
pub mod events;
pub mod ranking;
pub mod redemption;
pub mod storage;
pub mod storage_types;

// Re-exporting these makes them accessible as crate::rewards::UserRewards
pub use config::*;
pub use events::*;
pub use storage_types::{RewardsDataKey, UserRewards}; // Optional: re-exports config functions
