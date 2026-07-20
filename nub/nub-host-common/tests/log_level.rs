use nub_host_common::log_level::GuestLogFilter;

#[test]
fn guest_log_filter_u64_roundtrip() {
    let variants = [
        GuestLogFilter::Off,
        GuestLogFilter::Error,
        GuestLogFilter::Warn,
        GuestLogFilter::Info,
        GuestLogFilter::Debug,
        GuestLogFilter::Trace,
    ];

    for variant in variants {
        let as_u64: u64 = variant.into();
        let back = GuestLogFilter::try_from(as_u64).expect("conversion from u64 should succeed");
        assert_eq!(variant, back);
    }
}

#[test]
fn guest_log_filter_tracing_roundtrip() {
    let variants = [
        GuestLogFilter::Off,
        GuestLogFilter::Error,
        GuestLogFilter::Warn,
        GuestLogFilter::Info,
        GuestLogFilter::Debug,
        GuestLogFilter::Trace,
    ];

    for variant in variants {
        let tracing_filter: tracing_core::LevelFilter = variant.into();
        let back: GuestLogFilter = tracing_filter.into();
        assert_eq!(variant, back);
    }
}

#[test]
fn guest_log_filter_log_conversion() {
    let variants = [
        GuestLogFilter::Off,
        GuestLogFilter::Error,
        GuestLogFilter::Warn,
        GuestLogFilter::Info,
        GuestLogFilter::Debug,
        GuestLogFilter::Trace,
    ];

    let log_variants = [
        log::LevelFilter::Off,
        log::LevelFilter::Error,
        log::LevelFilter::Warn,
        log::LevelFilter::Info,
        log::LevelFilter::Debug,
        log::LevelFilter::Trace,
    ];

    for (variant, log_variant) in variants.into_iter().zip(log_variants) {
        let log_filter = log::LevelFilter::from(variant);
        assert_eq!(log_filter, log_variant);
    }
}

#[test]
fn guest_log_filter_try_from_u64_rejects_invalid() {
    // Any value outside the defined range [0, 5] should be rejected.
    assert!(GuestLogFilter::try_from(u64::MAX).is_err());
    assert!(GuestLogFilter::try_from(6).is_err());
}
