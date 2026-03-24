use soroban_sdk::contracterror;

/// Global error enum for the Nestera Savings Protocol
///
/// This enum defines all possible error conditions that can occur across
/// the savings contract modules. Each error is assigned a unique code
/// and provides a descriptive name for debugging and error handling.
///
/// Error codes range from 1-99 and are mapped to u32 for Soroban compatibility.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum SavingsError {
    // ========== Authorization Errors (1-9) ==========
    /// Returned when a caller is not authorized to perform the requested action.
    ///
    /// This typically occurs when:
    /// - A non-admin attempts to perform admin-only operations
    /// - A user tries to modify another user's savings plan
    /// - Invalid or missing authentication credentials
    Unauthorized = 1,

    // ========== User-Related Errors (10-19) ==========
    /// Returned when attempting to access a user that does not exist in the system.
    ///
    /// This occurs when:
    /// - Querying user data for an address that has never interacted with the contract
    /// - Attempting operations on non-existent user accounts
    UserNotFound = 10,

    /// Returned when attempting to create a user that already exists.
    ///
    /// This prevents duplicate user entries and maintains data integrity.
    UserAlreadyExists = 11,

    // ========== Savings Plan Errors (20-39) ==========
    /// Returned when attempting to access a savings plan that does not exist.
    ///
    /// This occurs when:
    /// - Querying a plan with an invalid plan_id
    /// - Attempting operations on deleted or non-existent plans
    PlanNotFound = 20,

    /// Returned when attempting to create a savings plan with a plan_id that already exists.
    ///
    /// Each savings plan must have a unique identifier within a user's account.
    DuplicatePlanId = 21,

    /// Returned when attempting to perform operations on a locked savings plan.
    ///
    /// This occurs when:
    /// - Trying to withdraw from a plan before the lock period expires
    /// - Attempting to modify a locked plan's parameters
    PlanLocked = 22,

    /// Returned when attempting to operate on a completed savings plan.
    ///
    /// Completed plans (e.g., achieved goal savings) may have restricted operations.
    PlanCompleted = 23,

    /// Returned when the maximum number of savings plans for a user is exceeded.
    ///
    /// This prevents resource exhaustion and maintains reasonable limits.
    MaxPlansExceeded = 24,

    /// Returned when attempting to create a plan with invalid configuration.
    ///
    /// This occurs when:
    /// - Plan parameters are inconsistent or contradictory
    /// - Required fields are missing for specific plan types
    InvalidPlanConfig = 25,

    // ========== Balance and Amount Errors (40-49) ==========
    /// Returned when attempting to withdraw more than the available balance.
    ///
    /// This occurs when:
    /// - Withdrawal amount exceeds the plan's current balance
    /// - Insufficient funds for the requested operation
    InsufficientBalance = 40,

    /// Returned when a deposit or withdrawal amount is zero or negative.
    ///
    /// All financial operations must involve positive amounts.
    InvalidAmount = 41,

    /// Returned when an amount exceeds the configured maximum limit.
    ///
    /// This may apply to single transactions or cumulative amounts.
    AmountExceedsLimit = 42,

    /// Returned when an amount is below the required minimum threshold.
    ///
    /// Some operations may require minimum amounts for efficiency or viability.
    AmountBelowMinimum = 43,

    // ========== Timestamp and Time-Related Errors (50-59) ==========
    /// Returned when timestamps are invalid or inconsistent.
    ///
    /// This occurs when:
    /// - Lock period end time is in the past
    /// - Start time is after end time
    /// - Timestamp values are unrealistic or malformed
    InvalidTimestamp = 50,

    /// Returned when attempting to perform an operation before the allowed time.
    ///
    /// This occurs when:
    /// - Withdrawing from a locked plan before maturity
    /// - Accessing time-gated features prematurely
    TooEarly = 51,

    /// Returned when attempting to perform an operation after the deadline.
    ///
    /// This may apply to time-limited offers or expiring opportunities.
    TooLate = 52,

    // ========== Interest and Yield Errors (60-69) ==========
    /// Returned when the specified interest rate is invalid.
    ///
    /// This occurs when:
    /// - Interest rate exceeds maximum allowed rate
    /// - Interest rate is negative
    /// - Rate format is incorrect
    InvalidInterestRate = 60,

    /// Returned when yield calculation fails or produces invalid results.
    ///
    /// This may occur due to overflow, underflow, or mathematical errors.
    YieldCalculationError = 61,

    // ========== Group Savings Errors (70-79) ==========
    /// Returned when attempting to join a group savings plan that is full.
    ///
    /// Group plans have maximum participant limits.
    GroupFull = 70,

    /// Returned when attempting to operate on a group plan as a non-member.
    ///
    /// Certain operations require active membership in the group.
    NotGroupMember = 71,

    /// Returned when the group savings cycle has not been completed.
    ///
    /// Some operations require the group cycle to finish first.
    GroupCycleIncomplete = 72,

    /// Returned when attempting to create a group with invalid parameters.
    ///
    /// This includes invalid member counts, contribution amounts, or schedules.
    InvalidGroupConfig = 73,

    // ========== General Contract Errors (80-99) ==========
    /// Returned when a required parameter is missing or null.
    ///
    /// All required fields must be provided for operations to proceed.
    MissingParameter = 80,

    /// Returned when contract data is corrupted or invalid.
    ///
    /// This is a critical error indicating storage or state inconsistency.
    DataCorruption = 81,

    /// Returned when an arithmetic operation results in overflow.
    ///
    /// This prevents silent overflow bugs in financial calculations.
    Overflow = 82,

    /// Returned when an arithmetic operation results in underflow.
    ///
    /// This prevents negative values in contexts requiring positive amounts.
    Underflow = 83,

    /// Returned when the contract is paused for maintenance or emergency.
    ///
    /// Admin can pause contract operations in case of detected issues.
    ContractPaused = 84,

    /// Returned when attempting an operation that has been deprecated.
    ///
    /// This helps guide users to updated APIs and functions.
    DeprecatedOperation = 85,

    /// Returned when an internal contract error occurs.
    ///
    /// This is a catch-all for unexpected internal errors.
    InternalError = 86,

    /// Returned when the provided asset or token is not supported.
    ///
    /// The contract may only support specific tokens for deposits.
    UnsupportedAsset = 87,

    /// Returned when signature verification fails.
    ///
    /// This occurs when authentication signatures are invalid or expired.
    InvalidSignature = 88,

    /// Returned when an operation would violate protocol invariants.
    ///
    /// This prevents state transitions that would break core assumptions.
    InvariantViolation = 89,

    /// Returned when a fee in basis points exceeds the maximum allowed (10000).
    ///
    /// Basis points range from 0 to 10000 (0% to 100%).
    InvalidFeeBps = 90,

    /// Returned when attempting to initialize config that is already configured.
    ///
    /// Config initialization can only happen once.
    ConfigAlreadyInitialized = 91,

    /// Returned when attempting to operate on a disabled strategy.
    ///
    /// Emergency withdraw has been executed and strategy is now disabled.
    StrategyDisabled = 92,

    /// Returned when the specified strategy does not exist.
    ///
    /// This occurs when querying a non-existent strategy.
    StrategyNotFound = 93,

    /// Returned when attempting to withdraw from a plan that has already been withdrawn.
    AlreadyWithdrawn = 94,

    /// Returned when the specified lock plan does not exist.
    LockNotFound = 95,

    /// Returned when attempting to register a strategy that already exists.
    StrategyAlreadyRegistered = 96,

    /// Returned when a reentrant call is detected during an external strategy interaction.
    ///
    /// This is triggered by the reentrancy guard when a second call tries to enter
    /// a strategy function while the first is still in progress.
    ReentrancyDetected = 97,

    /// Returned when an external strategy call returns an invalid response.
    ///
    /// E.g. the actual returned amount is 0 or negative when a positive value was expected.
    InvalidStrategyResponse = 98,
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn test_error_codes_are_unique() {
        // Verify that each error has a unique code
        let errors = std::vec![
            SavingsError::Unauthorized as u32,
            SavingsError::UserNotFound as u32,
            SavingsError::UserAlreadyExists as u32,
            SavingsError::PlanNotFound as u32,
            SavingsError::DuplicatePlanId as u32,
            SavingsError::PlanLocked as u32,
            SavingsError::PlanCompleted as u32,
            SavingsError::MaxPlansExceeded as u32,
            SavingsError::InvalidPlanConfig as u32,
            SavingsError::InsufficientBalance as u32,
            SavingsError::InvalidAmount as u32,
            SavingsError::AmountExceedsLimit as u32,
            SavingsError::AmountBelowMinimum as u32,
            SavingsError::InvalidTimestamp as u32,
            SavingsError::TooEarly as u32,
            SavingsError::TooLate as u32,
            SavingsError::InvalidInterestRate as u32,
            SavingsError::YieldCalculationError as u32,
            SavingsError::GroupFull as u32,
            SavingsError::NotGroupMember as u32,
            SavingsError::GroupCycleIncomplete as u32,
            SavingsError::InvalidGroupConfig as u32,
            SavingsError::MissingParameter as u32,
            SavingsError::DataCorruption as u32,
            SavingsError::Overflow as u32,
            SavingsError::Underflow as u32,
            SavingsError::ContractPaused as u32,
            SavingsError::DeprecatedOperation as u32,
            SavingsError::InternalError as u32,
            SavingsError::UnsupportedAsset as u32,
            SavingsError::InvalidSignature as u32,
            SavingsError::InvariantViolation as u32,
            SavingsError::InvalidFeeBps as u32,
            SavingsError::ConfigAlreadyInitialized as u32,
            SavingsError::StrategyNotFound as u32,
            SavingsError::StrategyAlreadyRegistered as u32,
            SavingsError::StrategyDisabled as u32,
            SavingsError::ReentrancyDetected as u32,
            SavingsError::InvalidStrategyResponse as u32,
        ];

        let mut sorted = errors.clone();
        sorted.sort();
        sorted.dedup();

        assert_eq!(errors.len(), sorted.len(), "Duplicate error codes detected");
    }

    #[test]
    fn test_error_ordering() {
        // Verify errors are properly ordered by their codes
        assert!(SavingsError::Unauthorized < SavingsError::UserNotFound);
        assert!(SavingsError::UserNotFound < SavingsError::PlanNotFound);
        assert!(SavingsError::PlanNotFound < SavingsError::InsufficientBalance);
    }

    #[test]
    fn test_error_code_values() {
        // Verify specific error codes match expected values
        assert_eq!(SavingsError::Unauthorized as u32, 1);
        assert_eq!(SavingsError::UserNotFound as u32, 10);
        assert_eq!(SavingsError::PlanNotFound as u32, 20);
        assert_eq!(SavingsError::InsufficientBalance as u32, 40);
        assert_eq!(SavingsError::InvalidTimestamp as u32, 50);
        assert_eq!(SavingsError::InvalidInterestRate as u32, 60);
        assert_eq!(SavingsError::GroupFull as u32, 70);
        assert_eq!(SavingsError::MissingParameter as u32, 80);
    }
}
