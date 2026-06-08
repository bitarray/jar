/// Maximum fixed execution lanes the guest runtime can address. The production
/// default vCPU pool is capped at 8; this leaves room for explicit overrides
/// while keeping lane-local hot state static and allocation-free.
pub const MAX_EXECUTION_LANES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExecutionLane {
    index: usize,
}

impl ExecutionLane {
    pub const PRIMARY: Self = Self { index: 0 };

    pub const fn new(index: usize) -> Self {
        Self { index }
    }

    pub const fn index(self) -> usize {
        self.index
    }

    pub fn assert_in_range(self) {
        assert!(
            self.index < MAX_EXECUTION_LANES,
            "execution lane index exceeds guest lane table"
        );
    }
}
