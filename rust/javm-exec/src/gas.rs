//! Gas counter: a non-negative u64 representing remaining budget.
//!
//! The execution engine decrements the counter per instruction (or
//! per ecall, etc.) and reports `ExitReason::OutOfGas` when it
//! would go negative. The actual gas-per-instruction cost table
//! lives at a higher layer (v3 spec: per-instruction debit happens
//! against the active Instance's gas slot's meter; the engine just
//! receives a single counter to decrement).

/// Gas type: `u64` remaining budget.
pub type Gas = u64;

/// Sentinel returned by `GasCounter::charge` on exhaustion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutOfGas;

/// Mutable gas counter with structured charge / check semantics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GasCounter {
    remaining: Gas,
}

impl GasCounter {
    /// Construct with the given initial budget.
    pub fn new(initial: Gas) -> Self {
        Self { remaining: initial }
    }

    /// Current remaining gas.
    pub fn remaining(&self) -> Gas {
        self.remaining
    }

    /// Try to deduct `cost`. Returns `Ok(())` on success or
    /// `Err(OutOfGas)` if the counter would go negative (caller
    /// should produce `ExitReason::OutOfGas`).
    #[inline(always)]
    pub fn charge(&mut self, cost: Gas) -> Result<(), OutOfGas> {
        match self.remaining.checked_sub(cost) {
            Some(new) => {
                self.remaining = new;
                Ok(())
            }
            None => {
                // Exhaust the counter so subsequent charges also fail.
                self.remaining = 0;
                Err(OutOfGas)
            }
        }
    }

    /// Set remaining gas explicitly (used by the higher layer's
    /// SetGasMeter operation for top-ups).
    pub fn set(&mut self, value: Gas) {
        self.remaining = value;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_remaining_matches_initial() {
        assert_eq!(GasCounter::new(1000).remaining(), 1000);
    }

    #[test]
    fn charge_within_budget_succeeds() {
        let mut g = GasCounter::new(100);
        assert!(g.charge(30).is_ok());
        assert_eq!(g.remaining(), 70);
        assert!(g.charge(70).is_ok());
        assert_eq!(g.remaining(), 0);
    }

    #[test]
    fn charge_over_budget_fails_and_exhausts() {
        let mut g = GasCounter::new(50);
        assert!(g.charge(100).is_err());
        assert_eq!(g.remaining(), 0);
        // Subsequent charges also fail.
        assert!(g.charge(1).is_err());
    }

    #[test]
    fn set_replaces_remaining() {
        let mut g = GasCounter::new(0);
        g.set(500);
        assert_eq!(g.remaining(), 500);
    }
}
