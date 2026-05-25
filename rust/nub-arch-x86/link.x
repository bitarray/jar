/* Linker script for the nub-arch-x86 guest kernel.
 *
 * Places the kernel at a canonical low-half VA inside the per-process
 * GUEST_VA reservation (GUEST_VA_BASE_DEFAULT + KERNEL_OFFSET =
 * 0x5000_0000_0000 + 0x1_4000_0000 = 0x5001_4000_0000). Low-half is
 * required so the host process (user-space, can only see canonical
 * low-half) can mmap-shadow the kernel at the same VA. The host's
 * initial PT (rust/nub-host-kvm/src/sandbox/snapshot.rs) maps the
 * low GPA range [BASE_ADDRESS, ...) to this GVA range via a constant
 * offset.
 *
 * Stays within a single 512 GiB PML4 slot so per-invocation ring-3
 * PTs (rust/nub-arch-x86/src/paging.rs) can inherit the kernel half
 * by shallow-copying PML4 entries without splitting tables.
 */

ENTRY(entrypoint)

SECTIONS {
    . = 0x500140000000;
    _kernel_start = .;

    /* ELF notes (hyperlight version note read by the host loader). */
    .note    : { KEEP(*(.note .note.*)) }

    .text    : { *(.text .text.*) }

    . = ALIGN(4096);
    .rodata  : { *(.rodata .rodata.*) }
    .data.rel.ro : { *(.data.rel.ro .data.rel.ro.*) }

    /* linkme distributed slices: guest_function registrations. KEEP
     * because nothing references the section by symbol at link time. */
    . = ALIGN(8);
    linkme_GUEST_FUNCTION_INIT_REGISTRATIONS : {
        KEEP(*(linkme_GUEST_FUNCTION_INIT_REGISTRATIONS))
    }
    linkm2_GUEST_FUNCTION_INIT_REGISTRATIONS : {
        KEEP(*(linkm2_GUEST_FUNCTION_INIT_REGISTRATIONS))
    }

    . = ALIGN(4096);
    .got     : { *(.got .got.plt) }
    .data    : { *(.data .data.*) }
    .bss     : { *(.bss .bss.* COMMON) }

    _kernel_end = .;

    /DISCARD/ : { *(.eh_frame) *(.gcc_except_table) *(.comment) }
}
