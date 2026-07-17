pub use nub_arch_x86_abi::MAX_EXECUTION_LANES;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExecutionLane {
    index: usize,
}

impl ExecutionLane {
    pub const PRIMARY: Self = Self { index: 0 };

    #[inline]
    pub const fn new(index: usize) -> Self {
        Self { index }
    }

    #[inline]
    pub const fn index(self) -> usize {
        self.index
    }

    #[inline]
    pub fn assert_in_range(self) {
        assert!(
            self.index < MAX_EXECUTION_LANES,
            "execution lane index exceeds guest lane table"
        );
    }
}
