//! Protocol configuration supporting different parameter profiles (tiny, full).
//!
//! The JAM protocol has two parameter sets: the "full" specification and a "tiny"
//! variant used for testing. This module provides a config type that holds these
//! parameters at runtime.

/// Protocol configuration parameters.
#[derive(Clone, Debug)]
pub struct Config {
    /// V: Total number of validators.
    pub validators_count: u16,
    /// C: Total number of cores.
    pub core_count: u16,
    /// E: Length of an epoch in timeslots.
    pub epoch_length: u32,
    /// K: Maximum tickets per extrinsic.
    pub max_tickets_per_block: u16,
    /// N: Ticket entries per validator.
    pub tickets_per_validator: u16,
    /// H: Recent history size.
    pub recent_history_size: usize,
    /// O: Authorization pool size.
    pub auth_pool_size: usize,
    /// Q: Authorization queue size.
    pub auth_queue_size: usize,
    /// U: Availability timeout in timeslots.
    pub availability_timeout: u32,
    /// D: Preimage expunge period in timeslots.
    pub preimage_expunge_period: u32,
    /// R: Rotation period in timeslots (chainspec-configurable).
    pub rotation_period_val: u32,
    /// Y: Ticket submission end / contest duration.
    pub ticket_submission_end_val: u32,
    /// W_P: Number of erasure-coded pieces per segment.
    pub erasure_pieces_per_segment: u32,
    /// G_T: Total gas across all accumulation.
    pub gas_total_accumulation: u64,
    /// G_R: Gas allocated for refine.
    pub gas_refine: u64,
}

impl Config {
    /// Full specification constants (Gray Paper v0.7.2).
    pub fn full() -> Self {
        Self {
            validators_count: 1023,
            core_count: 341,
            epoch_length: 600,
            max_tickets_per_block: 16,
            tickets_per_validator: 2,
            recent_history_size: 8,
            auth_pool_size: 8,
            auth_queue_size: 80,
            availability_timeout: 5,
            preimage_expunge_period: 19_200,
            rotation_period_val: 10,
            ticket_submission_end_val: 500,
            erasure_pieces_per_segment: 6,
            gas_total_accumulation: 3_500_000_000,
            gas_refine: 5_000_000_000,
        }
    }

    /// Tiny test configuration.
    pub fn tiny() -> Self {
        Self {
            validators_count: 6,
            core_count: 2,
            epoch_length: 12,
            max_tickets_per_block: 3,
            tickets_per_validator: 3,
            recent_history_size: 8,
            auth_pool_size: 8,
            auth_queue_size: 80,
            availability_timeout: 5,
            preimage_expunge_period: 32,
            rotation_period_val: 4,
            ticket_submission_end_val: 10,
            erasure_pieces_per_segment: 1_026,
            gas_total_accumulation: 20_000_000,
            gas_refine: 1_000_000_000,
        }
    }

    /// Validators super-majority threshold: ceil(2V/3) + 1.
    pub fn super_majority(&self) -> u16 {
        (self.validators_count * 2 / 3) + 1
    }

    /// Availability bitfield bytes: ceil(C / 8).
    pub fn avail_bitfield_bytes(&self) -> usize {
        ((self.core_count as usize) + 7) / 8
    }

    /// R: Rotation period in timeslots (from chainspec).
    pub fn rotation_period(&self) -> u32 {
        self.rotation_period_val
    }

    /// G: Number of guarantors per core = floor(V / C).
    pub fn guarantors_per_core(&self) -> u16 {
        self.validators_count / self.core_count
    }

    /// Rotations per epoch = floor(E / R).
    pub fn rotations_per_epoch(&self) -> u32 {
        let r = self.rotation_period();
        if r == 0 {
            return 0;
        }
        self.epoch_length / r
    }

    /// Y: Slot index at which ticket submission ends within an epoch (from chainspec).
    pub fn ticket_submission_end(&self) -> u32 {
        self.ticket_submission_end_val
    }

    /// Encode the protocol configuration blob (Gray Paper ΩY mode 0).
    /// 134 bytes: BI(8) BL(8) BS(8) C(2) D(4) E(4) GA(8) GI(8) GR(8) GT(8)
    ///            H(2) I(2) J(2) K(2) L(4) N(2) O(2) P(2) Q(2) R(2) T(2) U(2) V(2)
    ///            WA(4) WB(4) WC(4) WE(4) WM(4) WP(4) WR(4) WT(4) WX(4) Y(4)
    pub fn encode_config_blob(&self) -> Vec<u8> {
        use crate::constants::*;
        let mut buf = Vec::with_capacity(134);
        // E_8 values
        buf.extend_from_slice(&BALANCE_PER_ITEM.to_le_bytes());          // B_I
        buf.extend_from_slice(&BALANCE_PER_OCTET.to_le_bytes());         // B_L
        buf.extend_from_slice(&BALANCE_SERVICE_MINIMUM.to_le_bytes());   // B_S
        // E_2 values
        buf.extend_from_slice(&self.core_count.to_le_bytes());           // C
        // E_4 values
        buf.extend_from_slice(&self.preimage_expunge_period.to_le_bytes()); // D
        buf.extend_from_slice(&self.epoch_length.to_le_bytes());         // E
        // E_8 values
        buf.extend_from_slice(&GAS_ACCUMULATE.to_le_bytes());            // G_A
        buf.extend_from_slice(&GAS_IS_AUTHORIZED.to_le_bytes());         // G_I
        buf.extend_from_slice(&self.gas_refine.to_le_bytes());           // G_R
        buf.extend_from_slice(&self.gas_total_accumulation.to_le_bytes()); // G_T
        // E_2 values
        buf.extend_from_slice(&(self.recent_history_size as u16).to_le_bytes()); // H
        buf.extend_from_slice(&(MAX_WORK_ITEMS as u16).to_le_bytes());   // I
        buf.extend_from_slice(&(MAX_DEPENDENCY_ITEMS as u16).to_le_bytes()); // J
        buf.extend_from_slice(&self.max_tickets_per_block.to_le_bytes()); // K
        // E_4 value
        buf.extend_from_slice(&MAX_LOOKUP_ANCHOR_AGE.to_le_bytes());     // L
        // E_2 values
        buf.extend_from_slice(&self.tickets_per_validator.to_le_bytes()); // N
        buf.extend_from_slice(&(self.auth_pool_size as u16).to_le_bytes()); // O
        buf.extend_from_slice(&(SLOT_PERIOD_SECONDS as u16).to_le_bytes()); // P
        buf.extend_from_slice(&(self.auth_queue_size as u16).to_le_bytes()); // Q
        buf.extend_from_slice(&(self.rotation_period_val as u16).to_le_bytes()); // R
        buf.extend_from_slice(&(MAX_WORK_PACKAGE_EXTRINSICS as u16).to_le_bytes()); // T
        buf.extend_from_slice(&(self.availability_timeout as u16).to_le_bytes()); // U
        buf.extend_from_slice(&self.validators_count.to_le_bytes());     // V
        // E_4 values
        buf.extend_from_slice(&MAX_IS_AUTHORIZED_CODE_SIZE.to_le_bytes()); // W_A
        buf.extend_from_slice(&MAX_WORK_PACKAGE_BLOB_SIZE.to_le_bytes()); // W_B
        buf.extend_from_slice(&MAX_SERVICE_CODE_SIZE.to_le_bytes());     // W_C
        buf.extend_from_slice(&ERASURE_PIECE_SIZE.to_le_bytes());        // W_E
        buf.extend_from_slice(&MAX_IMPORTS.to_le_bytes());               // W_M
        buf.extend_from_slice(&self.erasure_pieces_per_segment.to_le_bytes()); // W_P
        buf.extend_from_slice(&MAX_WORK_REPORT_BLOB_SIZE.to_le_bytes()); // W_R
        buf.extend_from_slice(&(TRANSFER_MEMO_SIZE as u32).to_le_bytes()); // W_T
        buf.extend_from_slice(&MAX_EXPORTS.to_le_bytes());               // W_X
        buf.extend_from_slice(&self.ticket_submission_end_val.to_le_bytes()); // Y
        debug_assert_eq!(buf.len(), 134);
        buf
    }
}
