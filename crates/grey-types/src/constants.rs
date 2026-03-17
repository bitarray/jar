//! Protocol constants from Appendix I.4.4 of the Gray Paper.

/// A = 8: Period in seconds between audit tranches.
pub const AUDIT_TRANCHE_PERIOD: u32 = 8;

/// BI = 10: Additional minimum balance per item of elective service state.
pub const BALANCE_PER_ITEM: u64 = 10;

/// BL = 1: Additional minimum balance per octet of elective service state.
pub const BALANCE_PER_OCTET: u64 = 1;

/// BS = 100: Basic minimum balance for all services.
pub const BALANCE_SERVICE_MINIMUM: u64 = 100;

/// C = 341: Total number of cores.
pub const TOTAL_CORES: u16 = 341;

/// D = 19,200: Period in timeslots for preimage expunge eligibility.
pub const PREIMAGE_EXPUNGE_PERIOD: u32 = 19_200;

/// E = 600: Length of an epoch in timeslots.
pub const EPOCH_LENGTH: u32 = 600;

/// F = 2: Audit bias factor.
pub const AUDIT_BIAS_FACTOR: u32 = 2;

/// GA = 10,000,000: Gas allocated for Accumulation.
pub const GAS_ACCUMULATE: u64 = 10_000_000;

/// GI = 50,000,000: Gas allocated for Is-Authorized.
pub const GAS_IS_AUTHORIZED: u64 = 50_000_000;

/// GR = 5,000,000,000: Gas allocated for Refine.
pub const GAS_REFINE: u64 = 5_000_000_000;

/// GT = 3,500,000,000: Total gas across all Accumulation.
pub const GAS_TOTAL_ACCUMULATION: u64 = 3_500_000_000;

/// H = 8: Size of recent history in blocks.
pub const RECENT_HISTORY_SIZE: usize = 8;

/// I = 16: Maximum work items per package.
pub const MAX_WORK_ITEMS: usize = 16;

/// J = 8: Maximum sum of dependency items in a work-report.
pub const MAX_DEPENDENCY_ITEMS: usize = 8;

/// K = 16: Maximum tickets per extrinsic.
pub const MAX_TICKETS_PER_EXTRINSIC: usize = 16;

/// L = 14,400: Maximum age in timeslots of the lookup anchor.
pub const MAX_LOOKUP_ANCHOR_AGE: u32 = 14_400;

/// N = 2: Number of ticket entries per validator.
pub const TICKET_ENTRIES_PER_VALIDATOR: usize = 2;

/// O = 8: Maximum items in the authorizations pool.
pub const MAX_AUTH_POOL_ITEMS: usize = 8;

/// P = 6: Slot period in seconds.
pub const SLOT_PERIOD_SECONDS: u32 = 6;

/// Q = 80: Number of items in the authorizations queue.
pub const AUTH_QUEUE_SIZE: usize = 80;

/// R = 10: Rotation period of validator-core assignments in timeslots.
pub const ROTATION_PERIOD: u32 = 10;

/// S = 2^16: Minimum public service index.
pub const MIN_PUBLIC_SERVICE_INDEX: u32 = 1 << 16;

/// T = 128: Maximum number of extrinsics in a work-package.
pub const MAX_WORK_PACKAGE_EXTRINSICS: usize = 128;

/// U = 5: Period in timeslots after which unavailable work may be replaced.
pub const AVAILABILITY_TIMEOUT: u32 = 5;

/// V = 1023: Total number of validators.
pub const TOTAL_VALIDATORS: u16 = 1023;

/// WA = 64,000: Maximum size of is-authorized code in octets.
pub const MAX_IS_AUTHORIZED_CODE_SIZE: u32 = 64_000;

/// WB = 13,791,360: Maximum size of concatenated work-package blobs.
pub const MAX_WORK_PACKAGE_BLOB_SIZE: u32 = 13_791_360;

/// WC = 4,000,000: Maximum size of service code in octets.
pub const MAX_SERVICE_CODE_SIZE: u32 = 4_000_000;

/// WE = 684: Basic size of erasure-coded pieces in octets.
pub const ERASURE_PIECE_SIZE: u32 = 684;

/// WG = WP * WE = 4104: Size of a segment in octets.
pub const SEGMENT_SIZE: u32 = ERASURE_PIECES_PER_SEGMENT * ERASURE_PIECE_SIZE;

/// WM = 3,072: Maximum number of imports in a work-package.
pub const MAX_IMPORTS: u32 = 3_072;

/// WP = 6: Number of erasure-coded pieces per segment.
pub const ERASURE_PIECES_PER_SEGMENT: u32 = 6;

/// WR = 48 * 2^10: Maximum total size of unbounded blobs in a work-report.
pub const MAX_WORK_REPORT_BLOB_SIZE: u32 = 48 * 1024;

/// WT = 128: Size of a transfer memo in octets.
pub const TRANSFER_MEMO_SIZE: usize = 128;

/// WX = 3,072: Maximum number of exports in a work-package.
pub const MAX_EXPORTS: u32 = 3_072;

/// Y = 500: Slot index at which ticket submission ends within an epoch.
pub const TICKET_SUBMISSION_END: u32 = 500;

/// ZA = 2: PVM dynamic address alignment factor.
pub const PVM_ADDRESS_ALIGNMENT: u32 = 2;

/// Jam Common Era start: 1200 UTC on January 1, 2025.
/// Expressed as seconds since Unix epoch.
pub const JAM_EPOCH_UNIX: u64 = 1_735_732_800;

// ---------------------------------------------------------------------------
// Host-call return sentinels (GP Section B.4)
// ---------------------------------------------------------------------------

pub const HOST_OK: u64 = 0;
pub const HOST_NONE: u64 = u64::MAX;       // 2^64 - 1
pub const HOST_WHAT: u64 = u64::MAX - 1;   // 2^64 - 2
pub const HOST_OOB: u64 = u64::MAX - 2;    // 2^64 - 3
pub const HOST_WHO: u64 = u64::MAX - 3;    // 2^64 - 4
pub const HOST_FULL: u64 = u64::MAX - 4;   // 2^64 - 5
pub const HOST_CORE: u64 = u64::MAX - 5;   // 2^64 - 6
pub const HOST_CASH: u64 = u64::MAX - 6;   // 2^64 - 7
pub const HOST_LOW: u64 = u64::MAX - 7;    // 2^64 - 8
pub const HOST_HUH: u64 = u64::MAX - 8;    // 2^64 - 9
