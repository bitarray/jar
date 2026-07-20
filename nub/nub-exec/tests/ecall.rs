use nub_exec::{
    EcallHandler, EcallKind, EcallResult, ExitReason, Mem, Memory, PanickingHandler, Regs,
};

#[test]
fn panicking_handler_always_exits_panic() {
    let mut h = PanickingHandler;
    let mut regs = Regs::new();
    let mut mem = Mem::new();
    assert_eq!(
        h.handle(EcallKind::Ecall, &mut regs, &mut mem),
        EcallResult::Exit(ExitReason::Panic)
    );
    assert_eq!(
        h.handle(EcallKind::Ecalli(42), &mut regs, &mut mem),
        EcallResult::Exit(ExitReason::Panic)
    );
}

/// A handler that increments φ₀ on every ecall (any kind).
struct CountingHandler {
    count: u32,
}
impl EcallHandler for CountingHandler {
    fn handle(&mut self, _kind: EcallKind, regs: &mut Regs, _mem: &mut dyn Memory) -> EcallResult {
        self.count += 1;
        regs.write(0, regs.read(0).wrapping_add(1));
        EcallResult::Continue
    }
}

#[test]
fn counting_handler_mutates_regs_and_continues() {
    let mut h = CountingHandler { count: 0 };
    let mut regs = Regs::new();
    let mut mem = Mem::new();
    assert_eq!(
        h.handle(EcallKind::Ecall, &mut regs, &mut mem),
        EcallResult::Continue
    );
    assert_eq!(regs.read(0), 1);
    assert_eq!(
        h.handle(EcallKind::Ecalli(7), &mut regs, &mut mem),
        EcallResult::Continue
    );
    assert_eq!(regs.read(0), 2);
    assert_eq!(h.count, 2);
}
