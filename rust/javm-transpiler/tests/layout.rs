use javm_transpiler::layout::*;

#[test]
fn layout_minimal_stack_only() {
    // Data is laid out from DATA_BASE upward.
    let base = DATA_BASE / PVM_PAGE_SIZE;
    let l = ProgramLayout::compute(1, 0, 0, 0);
    assert_eq!(l.stack.cap_index, STACK_CAP_INDEX);
    assert_eq!(l.stack.base_page, base);
    assert_eq!(l.stack.page_count, 1);
    assert!(l.ro.is_none());
    assert!(l.rw.is_none());
    assert!(l.heap.is_none());
    assert_eq!(l.stack_top(), u64::from(DATA_BASE) + 4096);
    assert_eq!(l.total_data_pages(), 1);
}

#[test]
fn layout_full_stack_ro_rw_heap() {
    let base = DATA_BASE / PVM_PAGE_SIZE;
    let l = ProgramLayout::compute(2, 1, 1, 4);
    assert_eq!(l.stack.base_page, base);
    assert_eq!(l.ro.as_ref().unwrap().base_page, base + 2);
    assert_eq!(l.rw.as_ref().unwrap().base_page, base + 3);
    assert_eq!(l.heap.as_ref().unwrap().base_page, base + 4);
    assert_eq!(l.stack_top(), u64::from(DATA_BASE) + 2 * 4096);
    assert_eq!(l.total_data_pages(), 2 + 1 + 1 + 4);
}
