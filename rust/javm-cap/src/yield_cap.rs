//! `YieldSender` / `YieldReceiver` kernel-assisted cap helpers + the reserved
//! `kernel:*` yield-key namespace.
//!
//! A **yield_key** is a ≤[`MAX_KEY_LEN`](crate::slot::MAX_KEY_LEN)-byte
//! [`Key`] — the same byte-string key type used for cnode slots. It is the
//! routing key for `host_yield`: the kernel walks the call stack and the
//! nearest snapshotted [`YieldReceiver`](KernelImage::YieldReceiver) containing
//! the key catches the yield. Keys whose first byte is [`KERNEL_YIELD_NS`] are
//! reserved `kernel:*` syscalls, caught by the kernel as the implicit ROOT
//! YieldReceiver (bottom of the stack); chain/user yield_keys must not use that
//! namespace.
//!
//! The two per-Instance kernel-assisted variants:
//! - `YieldSender{yield_key}` — the EMIT right. The yield_key is packed into
//!   the handle's `regs[0..1]` (same packing as `Gas{meter_key}`; see
//!   [`key_to_regs`]).
//! - `YieldReceiver{Set<Key>}` — the CATCH right. The catch-set is serialized
//!   into the handle's `mem` DataCap so the kernel can short-circuit it during
//!   routing. Wire form: `u16 count` then, per key, `u8 len` + `len` bytes
//!   (the page-pad tail is ignored).

use alloc::vec::Vec;

use crate::NUM_REGS;
use crate::cache::CapHashOrRef;
use crate::cap::data::DataCap;
use crate::cap::instance::InstanceCap;
use crate::kernel_image::{KernelImage, kernel_image_hash, recognize_kernel_image};
use crate::slot::{Key, key_from_regs, key_to_regs};

/// Namespace marker (first byte) of a reserved `kernel:*` yield_key.
pub const KERNEL_YIELD_NS: u8 = 0xCE;

/// `kernel:mint_yield` — mint a (YieldSender, YieldReceiver) pair for a key.
pub const YK_MINT_YIELD: [u8; 2] = [KERNEL_YIELD_NS, 0x01];
/// `kernel:merge_yield_receiver` — union two YieldReceiver catch-sets.
pub const YK_MERGE_YIELD_RECEIVER: [u8; 2] = [KERNEL_YIELD_NS, 0x02];
/// `kernel:set_gas_meter` — set a meter, return previous.
pub const YK_SET_GAS_METER: [u8; 2] = [KERNEL_YIELD_NS, 0x03];
/// `kernel:mint_gas` — mint a `Gas{meter_key}` handle.
pub const YK_MINT_GAS: [u8; 2] = [KERNEL_YIELD_NS, 0x04];
/// `kernel:set_storage_quota` — set a quota, return previous.
pub const YK_SET_STORAGE_QUOTA: [u8; 2] = [KERNEL_YIELD_NS, 0x05];
/// `kernel:mint_quota` — mint a `Quota{quota_key}` handle.
pub const YK_MINT_QUOTA: [u8; 2] = [KERNEL_YIELD_NS, 0x06];
/// `kernel:oog` — kernel-injected on gas exhaustion.
pub const YK_OOG: [u8; 2] = [KERNEL_YIELD_NS, 0x10];
/// `kernel:storage_exhausted` — kernel-injected on quota exhaustion.
pub const YK_STORAGE_EXHAUSTED: [u8; 2] = [KERNEL_YIELD_NS, 0x11];
/// `kernel:attest` — attestation request (§15).
pub const YK_ATTEST: [u8; 2] = [KERNEL_YIELD_NS, 0x20];

/// True iff `key` is in the reserved `kernel:*` namespace (caught by the kernel
/// as the implicit root receiver).
pub fn is_kernel_yield_key(key: &Key) -> bool {
    key.as_slice().first() == Some(&KERNEL_YIELD_NS)
}

/// Build a `YieldSender{yield_key}` unit handle: a `Cap::Instance` with the
/// well-known YieldSender image-hash chain and the yield_key packed into
/// `regs[0..1]`.
pub fn yield_sender(yield_key: &Key) -> InstanceCap {
    unit_handle(KernelImage::YieldSender, yield_key)
}

/// Read the `yield_key` from a `YieldSender` handle. `None` if `inst` is not a
/// YieldSender.
pub fn yield_sender_key(inst: &InstanceCap) -> Option<Key> {
    unit_handle_key(KernelImage::YieldSender, inst)
}

/// Build a `YieldReceiver{keys}` unit handle: a `Cap::Instance` with the
/// well-known YieldReceiver image-hash chain and the catch-set serialized into
/// its `mem` DataCap. The set is normalized (sorted, deduped).
pub fn yield_receiver(keys: &[Key]) -> InstanceCap {
    let mut set: Vec<Key> = keys.to_vec();
    set.sort();
    set.dedup();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(set.len() as u16).to_le_bytes());
    for k in &set {
        let s = k.as_slice();
        bytes.push(s.len() as u8);
        bytes.extend_from_slice(s);
    }
    InstanceCap {
        image_hash_chain: kernel_image_hash(KernelImage::YieldReceiver),
        image_hash: [0u8; 32],
        root_cnode: CapHashOrRef::Hash([0u8; 32]),
        mem: DataCap::from_bytes(&bytes),
        regs: [0u64; NUM_REGS],
        pc: 0,
        gas_remaining: 0,
    }
}

/// Read the catch-set from a `YieldReceiver` handle (normalized: sorted,
/// deduped). `None` if `inst` is not a YieldReceiver; an empty/short mem
/// decodes to an empty set.
pub fn yield_receiver_keys(inst: &InstanceCap) -> Option<Vec<Key>> {
    if recognize_kernel_image(inst.image_hash_chain) != Some(KernelImage::YieldReceiver) {
        return None;
    }
    let len = inst.mem.content_len() as usize;
    if len < 2 {
        return Some(Vec::new());
    }
    let mut buf = alloc::vec![0u8; len];
    inst.mem.copy_into(0, &mut buf);
    let count = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    let mut keys = Vec::with_capacity(count);
    let mut off = 2usize;
    for _ in 0..count {
        if off >= buf.len() {
            break;
        }
        let klen = buf[off] as usize;
        off += 1;
        if off + klen > buf.len() {
            break;
        }
        keys.push(Key::from(&buf[off..off + klen]));
        off += klen;
    }
    Some(keys)
}

/// Union the catch-sets of two `YieldReceiver` handles (the
/// `kernel:merge_yield_receiver` operation). `None` if either is not a
/// YieldReceiver.
pub fn merge_yield_receivers(a: &InstanceCap, b: &InstanceCap) -> Option<InstanceCap> {
    let mut keys = yield_receiver_keys(a)?;
    keys.extend(yield_receiver_keys(b)?);
    Some(yield_receiver(&keys))
}

/// Build a `Gas{meter_key}` unit handle: a `Cap::Instance` with the well-known
/// Gas image-hash chain and the `meter_key` packed into `regs[0..1]` (same
/// packing as [`yield_sender`]). The kernel reads it from an Instance's
/// `gas_slots[0]` to index the gas-meter mapping; minted by the
/// `kernel:mint_gas` syscall.
pub fn gas_handle(meter_key: &Key) -> InstanceCap {
    unit_handle(KernelImage::Gas, meter_key)
}

/// Read the `meter_key` from a `Gas` handle. `None` if `inst` is not a Gas
/// handle.
pub fn gas_meter_key(inst: &InstanceCap) -> Option<Key> {
    unit_handle_key(KernelImage::Gas, inst)
}

/// Build a `Quota{quota_key}` unit handle (storage-quota analogue of
/// [`gas_handle`]); minted by the `kernel:mint_quota` syscall.
pub fn quota_handle(quota_key: &Key) -> InstanceCap {
    unit_handle(KernelImage::Quota, quota_key)
}

/// Read the `quota_key` from a `Quota` handle. `None` if `inst` is not a Quota
/// handle.
pub fn quota_key(inst: &InstanceCap) -> Option<Key> {
    unit_handle_key(KernelImage::Quota, inst)
}

/// A kernel unit handle naming a single `Key` (`Gas{meter_key}` /
/// `Quota{quota_key}` / `YieldSender{yield_key}`): a `Cap::Instance` carrying
/// `image`'s well-known image-hash chain with the key packed into `regs[0..1]`.
fn unit_handle(image: KernelImage, key: &Key) -> InstanceCap {
    let (packed, len) = key_to_regs(key);
    let mut regs = [0u64; NUM_REGS];
    regs[0] = packed;
    regs[1] = len;
    InstanceCap {
        image_hash_chain: kernel_image_hash(image),
        image_hash: [0u8; 32],
        root_cnode: CapHashOrRef::Hash([0u8; 32]),
        mem: DataCap::empty(),
        regs,
        pc: 0,
        gas_remaining: 0,
    }
}

/// Read the packed key from a unit handle, requiring it to carry `image`'s
/// image-hash chain.
fn unit_handle_key(image: KernelImage, inst: &InstanceCap) -> Option<Key> {
    if recognize_kernel_image(inst.image_hash_chain) != Some(image) {
        return None;
    }
    Some(key_from_regs(inst.regs[0], inst.regs[1]))
}
