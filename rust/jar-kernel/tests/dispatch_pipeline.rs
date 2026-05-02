//! Dispatch pipeline tests.
//!
//! Stub during the event-redesign migration. The old step-2/step-3
//! framing (with `slot_clear`, `Empty` SlotContent, `LiteUpdate`
//! broadcasts) is gone. The new model is a single `Vault.initialize`
//! per cycle for verify (fresh, ro-σ) and one persistent
//! `Vault.initialize` for process (rw-σ for transact, ro-σ for
//! dispatch). Tests for that pipeline land in Stage E (E1).

#[test]
fn dispatch_pipeline_stub() {
    // Placeholder so the test target keeps compiling. Real coverage
    // lands with the dispatch.rs / pool rewrite.
}
