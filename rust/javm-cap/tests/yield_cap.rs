//! `yield_cap` helpers: kernel yield-key namespace + YieldSender/YieldReceiver
//! construction/round-trip. Black-box against the public API.

use javm_cap::yield_cap::{
    KERNEL_YIELD_NS, YK_MINT_YIELD, YK_OOG, is_kernel_yield_key, merge_yield_receivers,
    yield_receiver, yield_receiver_keys, yield_sender, yield_sender_key,
};
use javm_cap::{Key, kernel_image_hash};

#[test]
fn kernel_keys_are_namespaced() {
    assert!(is_kernel_yield_key(&Key::from(&YK_MINT_YIELD[..])));
    assert!(is_kernel_yield_key(&Key::from(&YK_OOG[..])));
    assert_eq!(YK_MINT_YIELD[0], KERNEL_YIELD_NS);
    // A plain user key (single byte) is not in the kernel namespace.
    assert!(!is_kernel_yield_key(&Key::from(7u8)));
    // The empty key is not a kernel key.
    assert!(!is_kernel_yield_key(&Key::from(&[][..])));
}

#[test]
fn yield_sender_round_trips_its_key() {
    let key = Key::from(&[0xAB, 0xCD, 0xEF][..]);
    let sender = yield_sender(&key);
    // Identity is the well-known YieldSender image-hash chain.
    assert_eq!(
        sender.image_hash_chain,
        kernel_image_hash(javm_cap::KernelImage::YieldSender)
    );
    assert_eq!(yield_sender_key(&sender), Some(key));
}

#[test]
fn yield_sender_reads_kernel_key() {
    let mint = yield_sender(&Key::from(&YK_MINT_YIELD[..]));
    assert_eq!(yield_sender_key(&mint), Some(Key::from(&YK_MINT_YIELD[..])));
    assert!(is_kernel_yield_key(&yield_sender_key(&mint).unwrap()));
}

#[test]
fn non_yield_sender_returns_none() {
    // A YieldReceiver is not a YieldSender.
    let recv = yield_receiver(&[Key::from(1u8)]);
    assert_eq!(yield_sender_key(&recv), None);
}

#[test]
fn yield_receiver_round_trips_its_set() {
    let keys = [
        Key::from(1u8),
        Key::from(&YK_OOG[..]),
        Key::from(&[9, 9, 9][..]),
    ];
    let recv = yield_receiver(&keys);
    assert_eq!(
        recv.image_hash_chain,
        kernel_image_hash(javm_cap::KernelImage::YieldReceiver)
    );
    let mut got = yield_receiver_keys(&recv).expect("is a receiver");
    let mut want: Vec<Key> = keys.to_vec();
    want.sort();
    want.dedup();
    got.sort();
    assert_eq!(got, want);
}

#[test]
fn yield_receiver_normalizes_sort_and_dedup() {
    let recv = yield_receiver(&[Key::from(5u8), Key::from(1u8), Key::from(5u8)]);
    let got = yield_receiver_keys(&recv).expect("receiver");
    assert_eq!(got, vec![Key::from(1u8), Key::from(5u8)]);
}

#[test]
fn empty_receiver_decodes_to_empty_set() {
    let recv = yield_receiver(&[]);
    assert_eq!(yield_receiver_keys(&recv), Some(Vec::new()));
}

#[test]
fn merge_unions_catch_sets() {
    let a = yield_receiver(&[Key::from(1u8), Key::from(2u8)]);
    let b = yield_receiver(&[Key::from(2u8), Key::from(&YK_OOG[..])]);
    let merged = merge_yield_receivers(&a, &b).expect("both receivers");
    let got = yield_receiver_keys(&merged).expect("receiver");
    assert_eq!(
        got,
        vec![Key::from(1u8), Key::from(2u8), Key::from(&YK_OOG[..])]
    );
}
