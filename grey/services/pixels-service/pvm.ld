/* PVM-compatible linker script for JAM services.
 *
 * Places sections at addresses matching the PVM standard program layout:
 *   RO base = ZZ = 0x10000
 *   RW base = 2*ZZ + Z(ro_size) = 0x30000 (when ro_size < ZZ)
 *   .text can be anywhere (transpiler extracts it as code blob)
 */

ENTRY(_start)

SECTIONS
{
    /* Read-only data at PVM RO base (ZZ = 0x10000) */
    .rodata 0x10000 : { *(.rodata .rodata.* .srodata .srodata.*) }

    /* Code: placed after rodata. Address only matters for symbol resolution
       by the transpiler — not mapped in PVM memory. */
    .text 0x11000 : { *(.text .text.* .init .init.*) }

    /* Read-write data at PVM RW base (2*ZZ + ZZ = 0x30000) */
    .data 0x30000 : { *(.data .data.* .sdata .sdata.*) }
    .bss 0x30000 : { *(.bss .bss.* .sbss .sbss.* COMMON) }

    /DISCARD/ : { *(.eh_frame .eh_frame_hdr .comment .riscv.attributes) }
}
