/* Linker script for the nub-arch-x86 guest kernel.
 *
 * Places the kernel at the canonical "negative 2 GiB" high VA used by
 * most modern OS kernels (Linux uses 0xFFFFFFFF80000000 as well). The
 * host's initial PT (rust/nub-host-kvm/src/sandbox/snapshot.rs) maps
 * the low GPA range [BASE_ADDRESS, ...) to this high GVA range via a
 * constant offset.
 *
 * Stays within a single 512 GiB PML4 slot so per-invocation ring-3
 * PTs (rust/nub-arch-x86/src/paging.rs) can inherit the kernel half
 * by shallow-copying PML4 entries without splitting tables.
 */

ENTRY(entrypoint)

SECTIONS {
    . = 0xFFFFFFFF80000000;
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
