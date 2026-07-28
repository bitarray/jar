/* Linker script for the nub-arch-x86 guest kernel.
 *
 * The kernel binary is built as a position-independent executable
 * (DYN ELF) linked at VA 0; the host loader patches `R_X86_64_RELATIVE`
 * entries with the runtime base GVA (`guest_va_base() + KERNEL_OFFSET`
 * from `nub-host-common::layout`) at sandbox construction.
 *
 * Low-half is required so the host process (user-space, can only see
 * canonical low-half) can mmap-shadow the kernel at the same VA. The
 * host's initial PT (nub/nub-host-kvm/src/sandbox/snapshot.rs) maps
 * the low GPA range [BASE_ADDRESS, ...) to the chosen GVA range via
 * a constant offset.
 *
 * Stays within a single 512 GiB PML4 slot so per-invocation ring-3
 * PTs (nub/nub-arch-x86/src/paging.rs) can inherit the kernel half
 * by shallow-copying PML4 entries without splitting tables.
 */

ENTRY(entrypoint)

SECTIONS {
    /* Anchor at VA 0 so the binary stays PIE (DYN ELF). The host
     * loader patches `R_X86_64_RELATIVE` entries with the runtime
     * base GVA. */
    . = 0;
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
