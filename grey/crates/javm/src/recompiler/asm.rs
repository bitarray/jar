//! x86-64 assembler for PVM recompiler.
//!
//! Emits native x86-64 machine code with label-based jump resolution.
//! All jumps use 32-bit relative offsets (no short-jump optimization).

/// x86-64 register encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Reg {
    RAX = 0,
    RCX = 1,
    RDX = 2,
    RBX = 3,
    RSP = 4,
    RBP = 5,
    RSI = 6,
    RDI = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
}

impl Reg {
    /// Low 3 bits for ModR/M encoding.
    fn lo(self) -> u8 {
        (self as u8) & 7
    }
    /// High bit for REX.R or REX.B.
    fn hi(self) -> u8 {
        (self as u8) >> 3
    }
    /// Whether this register requires a REX prefix.
    fn needs_rex(self) -> bool {
        (self as u8) >= 8
    }
}

/// Condition codes for Jcc/SETcc/CMOVcc.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Cc {
    O = 0,
    NO = 1,
    B = 2,    // Below (unsigned <)
    AE = 3,   // Above or Equal (unsigned >=)
    E = 4,    // Equal
    NE = 5,   // Not Equal
    BE = 6,   // Below or Equal (unsigned <=)
    A = 7,    // Above (unsigned >)
    S = 8,    // Sign
    NS = 9,
    P = 10,
    NP = 11,
    L = 12,   // Less (signed <)
    GE = 13,  // Greater or Equal (signed >=)
    LE = 14,  // Less or Equal (signed <=)
    G = 15,   // Greater (signed >)
}

/// Label identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Label(pub u32);

/// Fixup kind for label resolution.
#[derive(Clone, Copy)]
struct Fixup {
    /// Offset in code buffer where the 4-byte rel32 placeholder is.
    offset: usize,
    /// The label this fixup targets.
    label: Label,
}

/// x86-64 assembler with label support.
pub struct Assembler {
    pub code: Vec<u8>,
    /// Label ID → bound offset (usize::MAX = unbound).
    labels: Vec<usize>,
    fixups: Vec<Fixup>,
}

const LABEL_UNBOUND: usize = usize::MAX;

impl Assembler {
    pub fn new() -> Self {
        Self {
            code: Vec::with_capacity(4096),
            labels: Vec::new(),
            fixups: Vec::new(),
        }
    }

    /// Create with pre-allocated capacity for code and labels.
    pub fn with_capacity(code_capacity: usize, label_capacity: usize) -> Self {
        Self {
            code: Vec::with_capacity(code_capacity),
            labels: Vec::with_capacity(label_capacity),
            fixups: Vec::with_capacity(label_capacity),
        }
    }

    /// Allocate a new label.
    pub fn new_label(&mut self) -> Label {
        let id = self.labels.len() as u32;
        self.labels.push(LABEL_UNBOUND);
        Label(id)
    }

    /// Bind a label to the current code position.
    pub fn bind_label(&mut self, label: Label) {
        self.labels[label.0 as usize] = self.code.len();
    }

    /// Current code offset.
    pub fn offset(&self) -> usize {
        self.code.len()
    }

    /// Patch an i32 value at a previously recorded offset.
    pub fn patch_i32(&mut self, offset: usize, value: i32) {
        self.code[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    // === Raw byte emission ===

    #[inline(always)]
    fn emit(&mut self, b: u8) {
        self.code.push(b);
    }

/// Emit 3 bytes at once.
    #[inline(always)]
    fn emit3(&mut self, a: u8, b: u8, c: u8) {
        self.code.extend_from_slice(&[a, b, c]);
    }

    fn emit_u32(&mut self, v: u32) {
        self.code.extend_from_slice(&v.to_le_bytes());
    }

    fn emit_u64(&mut self, v: u64) {
        self.code.extend_from_slice(&v.to_le_bytes());
    }

    fn emit_i32(&mut self, v: i32) {
        self.code.extend_from_slice(&v.to_le_bytes());
    }

    /// Emit a 4-byte placeholder for a label fixup, recording the fixup.
    fn emit_label_fixup(&mut self, label: Label) {
        let offset = self.code.len();
        self.fixups.push(Fixup { offset, label });
        self.emit_u32(0); // placeholder
    }

    // === REX prefix helpers ===

    /// REX prefix for 64-bit reg-reg operations.
    fn rex_w(&mut self, reg: Reg, rm: Reg) {
        self.emit(0x48 | (reg.hi() << 2) | rm.hi());
    }

    /// REX.W prefix for single-register operations.
    fn rex_w_b(&mut self, rm: Reg) {
        self.emit(0x48 | rm.hi());
    }

    /// Optional REX prefix for 32-bit ops (only if extended registers).
    fn rex_opt(&mut self, reg: Reg, rm: Reg) {
        let r = reg.hi();
        let b = rm.hi();
        if r != 0 || b != 0 {
            self.emit(0x40 | (r << 2) | b);
        }
    }

    fn rex_opt_b(&mut self, rm: Reg) {
        if rm.needs_rex() {
            self.emit(0x40 | rm.hi());
        }
    }

    /// ModR/M byte: mod=3 (register direct), reg, rm.
    fn modrm_rr(&mut self, reg: Reg, rm: Reg) {
        self.emit(0xC0 | (reg.lo() << 3) | rm.lo());
    }

    /// ModR/M byte: mod=2 (register + disp32), reg field, base.
    /// Emit ModR/M (+ optional SIB) + displacement for [base + disp] addressing.
    /// Automatically picks disp0 (mod=00), disp8 (mod=01), or disp32 (mod=10).
    fn modrm_disp(&mut self, reg: u8, base: Reg, disp: i32) {
        let bl = base.lo();
        let needs_sib = bl == 4; // RSP/R12 need SIB byte

        if disp == 0 && bl != 5 {
            // mod=00: no displacement (RBP/R13 can't use mod=00, it means RIP-relative)
            if needs_sib {
                self.emit((reg << 3) | 4);
                self.emit(0x24);
            } else {
                self.emit((reg << 3) | bl);
            }
        } else if disp >= -128 && disp <= 127 {
            // mod=01: disp8
            if needs_sib {
                self.emit(0x40 | (reg << 3) | 4);
                self.emit(0x24);
            } else {
                self.emit(0x40 | (reg << 3) | bl);
            }
            self.emit(disp as u8);
        } else {
            // mod=10: disp32
            if needs_sib {
                self.emit(0x80 | (reg << 3) | 4);
                self.emit(0x24);
            } else {
                self.emit(0x80 | (reg << 3) | bl);
            }
            self.emit_i32(disp);
        }
    }

    /// Emit ModR/M + displacement for [base + disp] with always-disp32 encoding.
    /// Used when the immediate after the displacement must be at a fixed offset
    /// (e.g., for patch-based gas metering where the imm32 is written later).
    fn modrm_disp32(&mut self, reg: u8, base: Reg, disp: i32) {
        if base.lo() == 4 {
            self.emit(0x80 | (reg << 3) | 4);
            self.emit(0x24);
        } else {
            self.emit(0x80 | (reg << 3) | base.lo());
        }
        self.emit_i32(disp);
    }

    // === Instruction emission ===

    // -- MOV --

    /// mov r64, r64
    pub fn mov_rr(&mut self, dst: Reg, src: Reg) {
        if dst == src { return; }
        self.emit3(
            0x48 | (src.hi() << 2) | dst.hi(),
            0x89,
            0xC0 | (src.lo() << 3) | dst.lo(),
        );
    }

    /// mov r64, imm64
    pub fn mov_ri64(&mut self, dst: Reg, imm: u64) {
        if imm == 0 {
            // xor r32, r32 (clears full r64)
            self.rex_opt(dst, dst);
            self.emit(0x31);
            self.modrm_rr(dst, dst);
        } else if imm <= u32::MAX as u64 {
            // mov r32, imm32 (zero-extends to 64)
            self.rex_opt_b(dst);
            self.emit(0xB8 + dst.lo());
            self.emit_u32(imm as u32);
        } else if imm as i64 >= i32::MIN as i64 && imm as i64 <= i32::MAX as i64 {
            // mov r64, sign-extended imm32
            self.rex_w_b(dst);
            self.emit(0xC7);
            self.emit(0xC0 | dst.lo());
            self.emit_i32(imm as i32);
        } else {
            // mov r64, imm64
            self.rex_w_b(dst);
            self.emit(0xB8 + dst.lo());
            self.emit_u64(imm);
        }
    }

    /// mov r32, imm32 (zero-extends to 64-bit)
    pub fn mov_ri32(&mut self, dst: Reg, imm: u32) {
        self.rex_opt_b(dst);
        self.emit(0xB8 + dst.lo());
        self.emit_u32(imm);
    }

    /// mov r32, [base + disp] — zero-extending 32-bit load
    pub fn mov_load32(&mut self, dst: Reg, base: Reg, disp: i32) {
        self.rex_opt(dst, base);
        self.emit(0x8B);
        self.modrm_disp(dst.lo(), base, disp);
    }

    /// mov r64, [base + disp]
    pub fn mov_load64(&mut self, dst: Reg, base: Reg, disp: i32) {
        self.rex_w(dst, base);
        self.emit(0x8B);
        self.modrm_disp(dst.lo(), base, disp);
    }

    /// movsxd r64, dword [base + index*4] — sign-extending load with SIB scale=4
    pub fn movsxd_load_sib4(&mut self, dst: Reg, base: Reg, index: Reg) {
        // REX.W prefix: 0x48 | (dst.hi << 2) | (index.hi << 1) | base.hi
        self.emit(0x48 | (dst.hi() << 2) | (index.hi() << 1) | base.hi());
        self.emit(0x63); // movsxd opcode
        // ModR/M: mod=00, reg=dst, rm=100 (SIB follows)
        self.emit((dst.lo() << 3) | 4);
        // SIB: scale=10 (4), index, base
        self.emit(0x80 | (index.lo() << 3) | base.lo());
    }

    /// mov dword [base + disp], r32 — 32-bit store
    pub fn mov_store32(&mut self, base: Reg, disp: i32, src: Reg) {
        self.rex_opt(src, base);
        self.emit(0x89);
        self.modrm_disp(src.lo(), base, disp);
    }

    /// mov [base + disp], r64
    pub fn mov_store64(&mut self, base: Reg, disp: i32, src: Reg) {
        self.rex_w(src, base);
        self.emit(0x89);
        self.modrm_disp(src.lo(), base, disp);
    }

    /// mov dword [base + disp], imm32
    pub fn mov_store32_imm(&mut self, base: Reg, disp: i32, imm: i32) {
        self.rex_opt_b(base);
        self.emit(0xC7);
        self.modrm_disp(0, base, disp);
        self.emit_i32(imm);
    }

    /// mov qword [base + disp], sign-extended imm32
    pub fn mov_store64_imm(&mut self, base: Reg, disp: i32, imm: i32) {
        self.rex_w_b(base);
        self.emit(0xC7);
        self.modrm_disp(0, base, disp);
        self.emit_i32(imm);
    }

    // -- SIB-based memory access [base + index] --

    /// Emit ModR/M + SIB for [base + index] addressing (scale=1, no displacement).
    /// Special case: base=RBP/R13 requires mod=01 with disp8=0.
    fn modrm_sib_base_index(&mut self, reg: u8, base: Reg, index: Reg) {
        if base.lo() == 5 {
            // RBP/R13: mod=01, rm=100 (SIB), disp8=0
            self.emit(0x44 | (reg << 3)); // ModR/M: mod=01, reg, rm=100
            self.emit((index.lo() << 3) | base.lo()); // SIB: scale=00, index, base
            self.emit(0); // disp8 = 0
        } else {
            // mod=00, rm=100 (SIB)
            self.emit((reg << 3) | 4); // ModR/M
            self.emit((index.lo() << 3) | base.lo()); // SIB: scale=00, index, base
        }
    }

    /// movzx r64, byte [base + index] — zero-extending u8 load
    pub fn movzx_load8_sib(&mut self, dst: Reg, base: Reg, index: Reg) {
        self.emit(0x48 | (dst.hi() << 2) | (index.hi() << 1) | base.hi());
        self.emit(0x0F);
        self.emit(0xB6);
        self.modrm_sib_base_index(dst.lo(), base, index);
    }

    /// movzx r32, word [base + index] — zero-extending u16 load
    pub fn movzx_load16_sib(&mut self, dst: Reg, base: Reg, index: Reg) {
        let rex = 0x40 | (dst.hi() << 2) | (index.hi() << 1) | base.hi();
        if rex != 0x40 { self.emit(rex); }
        self.emit(0x0F);
        self.emit(0xB7);
        self.modrm_sib_base_index(dst.lo(), base, index);
    }

    /// mov r32, dword [base + index] — zero-extending u32 load
    pub fn mov_load32_sib(&mut self, dst: Reg, base: Reg, index: Reg) {
        let rex = 0x40 | (dst.hi() << 2) | (index.hi() << 1) | base.hi();
        if rex != 0x40 { self.emit(rex); }
        self.emit(0x8B);
        self.modrm_sib_base_index(dst.lo(), base, index);
    }

    /// mov r64, qword [base + index]
    pub fn mov_load64_sib(&mut self, dst: Reg, base: Reg, index: Reg) {
        self.emit(0x48 | (dst.hi() << 2) | (index.hi() << 1) | base.hi());
        self.emit(0x8B);
        self.modrm_sib_base_index(dst.lo(), base, index);
    }

    /// mov byte [base + index], r8
    pub fn mov_store8_sib(&mut self, base: Reg, index: Reg, src: Reg) {
        // Need REX for uniform byte reg access (SPL etc)
        self.emit(0x40 | (src.hi() << 2) | (index.hi() << 1) | base.hi());
        self.emit(0x88);
        self.modrm_sib_base_index(src.lo(), base, index);
    }

    /// mov word [base + index], r16
    pub fn mov_store16_sib(&mut self, base: Reg, index: Reg, src: Reg) {
        self.emit(0x66); // operand size prefix
        let rex = 0x40 | (src.hi() << 2) | (index.hi() << 1) | base.hi();
        if rex != 0x40 { self.emit(rex); }
        self.emit(0x89);
        self.modrm_sib_base_index(src.lo(), base, index);
    }

    /// mov dword [base + index], r32
    pub fn mov_store32_sib(&mut self, base: Reg, index: Reg, src: Reg) {
        let rex = 0x40 | (src.hi() << 2) | (index.hi() << 1) | base.hi();
        if rex != 0x40 { self.emit(rex); }
        self.emit(0x89);
        self.modrm_sib_base_index(src.lo(), base, index);
    }

    /// mov qword [base + index], r64
    pub fn mov_store64_sib(&mut self, base: Reg, index: Reg, src: Reg) {
        self.emit(0x48 | (src.hi() << 2) | (index.hi() << 1) | base.hi());
        self.emit(0x89);
        self.modrm_sib_base_index(src.lo(), base, index);
    }

    /// add r64, qword [base + disp32]
    pub fn add_r64_mem(&mut self, dst: Reg, base: Reg, disp: i32) {
        self.rex_w(dst, base);
        self.emit(0x03);
        self.modrm_disp(dst.lo(), base, disp);
    }

    /// movzx r64, byte [rax] (simple deref, no SIB needed) — for perm table lookup
    pub fn movzx_load8_deref(&mut self, dst: Reg, base: Reg) {
        self.emit(0x48 | (dst.hi() << 2) | base.hi());
        self.emit(0x0F);
        self.emit(0xB6);
        if base.lo() == 5 {
            // RBP/R13: need mod=01, disp8=0
            self.emit((dst.lo() << 3) | base.lo() | 0x40);
            self.emit(0);
        } else if base.lo() == 4 {
            // RSP/R12: need SIB
            self.emit((dst.lo() << 3) | 4);
            self.emit(0x24);
        } else {
            self.emit((dst.lo() << 3) | base.lo());
        }
    }

    /// cmp byte [base + index + disp32], imm8 — compare memory byte with SIB+displacement
    pub fn cmp_byte_sib_disp32(&mut self, base: Reg, index: Reg, disp: i32, imm: u8) {
        // REX prefix for extended registers
        let rex = 0x40 | (index.hi() << 1) | base.hi();
        if rex != 0x40 { self.emit(rex); }
        self.emit(0x80); // ALU r/m8, imm8
        // ModR/M: mod=10 (disp32), reg=/7 (CMP), rm=100 (SIB)
        self.emit(0xBC); // 10_111_100
        // SIB: scale=00, index, base
        self.emit((index.lo() << 3) | base.lo());
        self.emit_i32(disp);
        self.emit(imm);
    }

    /// cmp byte [reg], imm8 — compare memory byte with immediate
    pub fn cmp_byte_deref_imm(&mut self, base: Reg, imm: u8) {
        // REX prefix needed for R8-R15 base
        if base.needs_rex() {
            self.emit(0x41 | base.hi());
        }
        self.emit(0x80); // ALU r/m8, imm8
        // ModR/M: mod depends on base register
        if base.lo() == 5 {
            // RBP/R13: need mod=01, disp8=0
            self.emit(0x78 | base.lo()); // /7 = CMP, mod=01
            self.emit(0); // disp8
        } else if base.lo() == 4 {
            // RSP/R12: need SIB
            self.emit(0x38 | 4); // /7 = CMP, mod=00, rm=100
            self.emit(0x24); // SIB: base=RSP/R12
        } else {
            self.emit(0x38 | base.lo()); // /7 = CMP, mod=00
        }
        self.emit(imm);
    }

    // -- ALU reg,reg (64-bit) --

    fn alu_rr64(&mut self, op: u8, dst: Reg, src: Reg) {
        self.rex_w(src, dst);
        self.emit(op);
        self.modrm_rr(src, dst);
    }

    fn alu_rr32(&mut self, op: u8, dst: Reg, src: Reg) {
        self.rex_opt(src, dst);
        self.emit(op);
        self.modrm_rr(src, dst);
    }

    pub fn add_rr(&mut self, dst: Reg, src: Reg) { self.alu_rr64(0x01, dst, src); }
    pub fn sub_rr(&mut self, dst: Reg, src: Reg) { self.alu_rr64(0x29, dst, src); }
    pub fn and_rr(&mut self, dst: Reg, src: Reg) { self.alu_rr64(0x21, dst, src); }
    pub fn or_rr(&mut self, dst: Reg, src: Reg) { self.alu_rr64(0x09, dst, src); }
    pub fn xor_rr(&mut self, dst: Reg, src: Reg) { self.alu_rr64(0x31, dst, src); }
    pub fn cmp_rr(&mut self, a: Reg, b: Reg) { self.alu_rr64(0x39, a, b); }
    pub fn test_rr(&mut self, a: Reg, b: Reg) { self.alu_rr64(0x85, a, b); }

    pub fn add_rr32(&mut self, dst: Reg, src: Reg) { self.alu_rr32(0x01, dst, src); }
    pub fn sub_rr32(&mut self, dst: Reg, src: Reg) { self.alu_rr32(0x29, dst, src); }

    // -- ALU reg,imm (64-bit) --
    // Uses imm8 (opcode 0x83) when immediate fits in -128..127, saving 3 bytes.

    fn alu_ri64(&mut self, ext: u8, dst: Reg, imm: i32) {
        self.rex_w_b(dst);
        if imm >= -128 && imm <= 127 {
            self.emit(0x83);
            self.emit(0xC0 | (ext << 3) | dst.lo());
            self.emit(imm as u8);
        } else {
            self.emit(0x81);
            self.emit(0xC0 | (ext << 3) | dst.lo());
            self.emit_i32(imm);
        }
    }

    fn alu_ri32(&mut self, ext: u8, dst: Reg, imm: i32) {
        self.rex_opt_b(dst);
        if imm >= -128 && imm <= 127 {
            self.emit(0x83);
            self.emit(0xC0 | (ext << 3) | dst.lo());
            self.emit(imm as u8);
        } else {
            self.emit(0x81);
            self.emit(0xC0 | (ext << 3) | dst.lo());
            self.emit_i32(imm);
        }
    }

    pub fn add_ri(&mut self, dst: Reg, imm: i32) { self.alu_ri64(0, dst, imm); }
    pub fn sub_ri(&mut self, dst: Reg, imm: i32) { self.alu_ri64(5, dst, imm); }
    pub fn and_ri(&mut self, dst: Reg, imm: i32) { self.alu_ri64(4, dst, imm); }
    pub fn or_ri(&mut self, dst: Reg, imm: i32) { self.alu_ri64(1, dst, imm); }
    pub fn xor_ri(&mut self, dst: Reg, imm: i32) { self.alu_ri64(6, dst, imm); }
    pub fn cmp_ri(&mut self, a: Reg, imm: i32) { self.alu_ri64(7, a, imm); }

    pub fn add_ri32(&mut self, dst: Reg, imm: i32) { self.alu_ri32(0, dst, imm); }
    pub fn sub_ri32(&mut self, dst: Reg, imm: i32) { self.alu_ri32(5, dst, imm); }
    pub fn cmp_ri32(&mut self, a: Reg, imm: i32) { self.alu_ri32(7, a, imm); }

    /// cmp dword [base + disp], imm32
    pub fn cmp_mem32_imm(&mut self, base: Reg, disp: i32, imm: i32) {
        if base.hi() != 0 {
            self.emit(0x41);             // REX.B for extended base register
        }
        self.emit(0x81);                 // ALU r/m32, imm32
        self.modrm_disp(7, base, disp);
        self.emit_i32(imm);
    }

    /// cmp dword [base + disp], reg32  (sets flags: mem vs reg)
    pub fn cmp_mem32_r(&mut self, base: Reg, disp: i32, src: Reg) {
        if base.hi() != 0 || src.hi() != 0 {
            self.emit(0x40 | src.hi() << 2 | base.hi()); // REX
        }
        self.emit(0x39);                 // CMP r/m32, r32
        self.modrm_disp(src.lo(), base, disp);
    }

    /// sub qword [base + disp32], sign-extended imm32.
    /// Always uses disp32 encoding (the imm32 is patched after emission for gas metering).
    pub fn sub_mem64_imm32(&mut self, base: Reg, disp: i32, imm: i32) {
        self.rex_w_b(base);          // REX.W (+ REX.B if base is R8-R15)
        self.emit(0x81);             // ALU r/m64, imm32
        self.modrm_disp32(5, base, disp);
        self.emit_i32(imm);
    }

    /// add qword [base + disp32], imm32
    pub fn add_mem64_imm32(&mut self, base: Reg, disp: i32, imm: i32) {
        self.rex_w_b(base);          // REX.W (+ REX.B if base is R8-R15)
        self.emit(0x81);             // ALU r/m64, imm32
        self.modrm_disp32(0, base, disp);
        self.emit_i32(imm);
    }

    // -- IMUL --

    /// imul r64, r64
    pub fn imul_rr(&mut self, dst: Reg, src: Reg) {
        self.rex_w(dst, src);
        self.emit(0x0F);
        self.emit(0xAF);
        self.modrm_rr(dst, src);
    }

    /// imul r32, r32
    pub fn imul_rr32(&mut self, dst: Reg, src: Reg) {
        self.rex_opt(dst, src);
        self.emit(0x0F);
        self.emit(0xAF);
        self.modrm_rr(dst, src);
    }

    /// imul r64, r64, imm32
    pub fn imul_rri(&mut self, dst: Reg, src: Reg, imm: i32) {
        self.rex_w(dst, src);
        self.emit(0x69);
        self.modrm_rr(dst, src);
        self.emit_i32(imm);
    }

    /// imul r32, r32, imm32
    pub fn imul_rri32(&mut self, dst: Reg, src: Reg, imm: i32) {
        self.rex_opt(dst, src);
        self.emit(0x69);
        self.modrm_rr(dst, src);
        self.emit_i32(imm);
    }

    // -- MUL/IMUL widening (RDX:RAX = RAX * src) --

    /// mul r64 (unsigned RDX:RAX = RAX * src)
    pub fn mul_rdx_rax(&mut self, src: Reg) {
        self.rex_w_b(src);
        self.emit(0xF7);
        self.emit(0xE0 | src.lo()); // /4
    }

    /// imul r64 (signed RDX:RAX = RAX * src)
    pub fn imul_rdx_rax(&mut self, src: Reg) {
        self.rex_w_b(src);
        self.emit(0xF7);
        self.emit(0xE8 | src.lo()); // /5
    }

    // -- DIV/IDIV --

    /// div r64 (unsigned RAX = RDX:RAX / src, RDX = remainder)
    pub fn div64(&mut self, src: Reg) {
        self.rex_w_b(src);
        self.emit(0xF7);
        self.emit(0xF0 | src.lo()); // /6
    }

    /// idiv r64 (signed)
    pub fn idiv64(&mut self, src: Reg) {
        self.rex_w_b(src);
        self.emit(0xF7);
        self.emit(0xF8 | src.lo()); // /7
    }

    /// div r32
    pub fn div32(&mut self, src: Reg) {
        self.rex_opt_b(src);
        self.emit(0xF7);
        self.emit(0xF0 | src.lo());
    }

    /// idiv r32
    pub fn idiv32(&mut self, src: Reg) {
        self.rex_opt_b(src);
        self.emit(0xF7);
        self.emit(0xF8 | src.lo());
    }

    /// cqo (sign-extend RAX into RDX:RAX, 64-bit)
    pub fn cqo(&mut self) {
        self.emit(0x48);
        self.emit(0x99);
    }

    /// cdq (sign-extend EAX into EDX:EAX, 32-bit)
    pub fn cdq(&mut self) {
        self.emit(0x99);
    }

    // -- INC/DEC --

    /// inc r64
    pub fn inc64(&mut self, dst: Reg) {
        self.rex_w_b(dst);
        self.emit(0xFF);
        self.emit(0xC0 | dst.lo()); // /0
    }

    /// dec r64
    pub fn dec64(&mut self, dst: Reg) {
        self.rex_w_b(dst);
        self.emit(0xFF);
        self.emit(0xC8 | dst.lo()); // /1
    }

    // -- NEG/NOT --

    /// neg r64
    pub fn neg64(&mut self, dst: Reg) {
        self.rex_w_b(dst);
        self.emit(0xF7);
        self.emit(0xD8 | dst.lo()); // /3
    }

    /// not r64
    pub fn not64(&mut self, dst: Reg) {
        self.rex_w_b(dst);
        self.emit(0xF7);
        self.emit(0xD0 | dst.lo()); // /2
    }

    // -- Shifts --

    fn shift_ri64(&mut self, ext: u8, dst: Reg, imm: u8) {
        self.rex_w_b(dst);
        self.emit(0xC1);
        self.emit(0xC0 | (ext << 3) | dst.lo());
        self.emit(imm);
    }

    pub fn shift_cl64(&mut self, ext: u8, dst: Reg) {
        self.rex_w_b(dst);
        self.emit(0xD3);
        self.emit(0xC0 | (ext << 3) | dst.lo());
    }

    fn shift_ri32(&mut self, ext: u8, dst: Reg, imm: u8) {
        self.rex_opt_b(dst);
        self.emit(0xC1);
        self.emit(0xC0 | (ext << 3) | dst.lo());
        self.emit(imm);
    }

    pub fn shift_cl32(&mut self, ext: u8, dst: Reg) {
        self.rex_opt_b(dst);
        self.emit(0xD3);
        self.emit(0xC0 | (ext << 3) | dst.lo());
    }

    pub fn shl_ri64(&mut self, dst: Reg, imm: u8) { self.shift_ri64(4, dst, imm); }
    pub fn shr_ri64(&mut self, dst: Reg, imm: u8) { self.shift_ri64(5, dst, imm); }
    pub fn sar_ri64(&mut self, dst: Reg, imm: u8) { self.shift_ri64(7, dst, imm); }
    pub fn shl_cl64(&mut self, dst: Reg) { self.shift_cl64(4, dst); }
    pub fn shr_cl64(&mut self, dst: Reg) { self.shift_cl64(5, dst); }
    pub fn sar_cl64(&mut self, dst: Reg) { self.shift_cl64(7, dst); }
    pub fn rol_cl64(&mut self, dst: Reg) { self.shift_cl64(0, dst); }
    pub fn ror_cl64(&mut self, dst: Reg) { self.shift_cl64(1, dst); }
    pub fn rol_ri64(&mut self, dst: Reg, imm: u8) { self.shift_ri64(0, dst, imm); }
    pub fn ror_ri64(&mut self, dst: Reg, imm: u8) { self.shift_ri64(1, dst, imm); }

    pub fn shl_ri32(&mut self, dst: Reg, imm: u8) { self.shift_ri32(4, dst, imm); }
    pub fn shr_ri32(&mut self, dst: Reg, imm: u8) { self.shift_ri32(5, dst, imm); }
    pub fn sar_ri32(&mut self, dst: Reg, imm: u8) { self.shift_ri32(7, dst, imm); }
    pub fn shl_cl32(&mut self, dst: Reg) { self.shift_cl32(4, dst); }
    pub fn shr_cl32(&mut self, dst: Reg) { self.shift_cl32(5, dst); }
    pub fn sar_cl32(&mut self, dst: Reg) { self.shift_cl32(7, dst); }
    pub fn rol_cl32(&mut self, dst: Reg) { self.shift_cl32(0, dst); }
    pub fn ror_cl32(&mut self, dst: Reg) { self.shift_cl32(1, dst); }
    pub fn rol_ri32(&mut self, dst: Reg, imm: u8) { self.shift_ri32(0, dst, imm); }
    pub fn ror_ri32(&mut self, dst: Reg, imm: u8) { self.shift_ri32(1, dst, imm); }

    // -- Extensions --

    /// movsxd r64, r32 (sign-extend 32→64)
    pub fn movsxd(&mut self, dst: Reg, src: Reg) {
        self.rex_w(dst, src);
        self.emit(0x63);
        self.modrm_rr(dst, src);
    }

    /// movsx r64, r8 (sign-extend 8→64)
    pub fn movsx_8_64(&mut self, dst: Reg, src: Reg) {
        self.rex_w(dst, src);
        self.emit(0x0F);
        self.emit(0xBE);
        self.modrm_rr(dst, src);
    }

    /// movsx r64, r16 (sign-extend 16→64)
    pub fn movsx_16_64(&mut self, dst: Reg, src: Reg) {
        self.rex_w(dst, src);
        self.emit(0x0F);
        self.emit(0xBF);
        self.modrm_rr(dst, src);
    }

    /// movzx r64, r8 (zero-extend 8→64)
    pub fn movzx_8_64(&mut self, dst: Reg, src: Reg) {
        // REX.W not strictly needed since movzx r32,r8 zero-extends, but it's
        // needed for R8-R15 access and consistency.
        self.rex_w(dst, src);
        self.emit(0x0F);
        self.emit(0xB6);
        self.modrm_rr(dst, src);
    }

    /// movzx r32, r16 (zero-extends to 64 due to 32-bit operation)
    pub fn movzx_16_64(&mut self, dst: Reg, src: Reg) {
        self.rex_opt(dst, src);
        self.emit(0x0F);
        self.emit(0xB7);
        self.modrm_rr(dst, src);
    }

    /// Zero-extend 32→64: mov r32, r32 (implicit zero-extend)
    pub fn movzx_32_64(&mut self, dst: Reg, src: Reg) {
        // mov r32, r32 zero-extends into the full 64-bit register
        self.rex_opt(src, dst);
        self.emit(0x89);
        self.modrm_rr(src, dst);
    }

    // -- Conditional set --

    /// setcc r8 (sets low byte, need to movzx after)
    pub fn setcc(&mut self, cc: Cc, dst: Reg) {
        // REX prefix needed for R8-R15 (and to access SPL/BPL/SIL/DIL)
        if dst.needs_rex() || matches!(dst, Reg::RSP | Reg::RBP | Reg::RSI | Reg::RDI) {
            self.emit(0x40 | dst.hi());
        }
        self.emit(0x0F);
        self.emit(0x90 + cc as u8);
        self.emit(0xC0 | dst.lo());
    }

    /// cmovcc r64, r64
    pub fn cmovcc(&mut self, cc: Cc, dst: Reg, src: Reg) {
        self.rex_w(dst, src);
        self.emit(0x0F);
        self.emit(0x40 + cc as u8);
        self.modrm_rr(dst, src);
    }

    // -- Bit manipulation (require BMI/POPCNT support) --

    /// popcnt r64, r64
    pub fn popcnt64(&mut self, dst: Reg, src: Reg) {
        self.emit(0xF3);
        self.rex_w(dst, src);
        self.emit(0x0F);
        self.emit(0xB8);
        self.modrm_rr(dst, src);
    }

    /// lzcnt r64, r64
    pub fn lzcnt64(&mut self, dst: Reg, src: Reg) {
        self.emit(0xF3);
        self.rex_w(dst, src);
        self.emit(0x0F);
        self.emit(0xBD);
        self.modrm_rr(dst, src);
    }

    /// tzcnt r64, r64
    pub fn tzcnt64(&mut self, dst: Reg, src: Reg) {
        self.emit(0xF3);
        self.rex_w(dst, src);
        self.emit(0x0F);
        self.emit(0xBC);
        self.modrm_rr(dst, src);
    }

    /// bswap r64
    pub fn bswap64(&mut self, dst: Reg) {
        self.rex_w_b(dst);
        self.emit(0x0F);
        self.emit(0xC8 + dst.lo());
    }

    // -- Stack --

    pub fn push(&mut self, reg: Reg) {
        self.rex_opt_b(reg);
        self.emit(0x50 + reg.lo());
    }

    pub fn pop(&mut self, reg: Reg) {
        self.rex_opt_b(reg);
        self.emit(0x58 + reg.lo());
    }

    // -- Branches and jumps --

    /// jmp to label — uses rel8 for backward jumps within ±127 bytes.
    pub fn jmp_label(&mut self, label: Label) {
        let bound = self.labels[label.0 as usize];
        if bound != LABEL_UNBOUND {
            let target = bound;
            // Backward jump — label already bound, try rel8.
            // rel8 offset = target - (current + 2), where 2 = size of jmp rel8
            let rel = target as isize - (self.code.len() as isize + 2);
            if rel >= i8::MIN as isize && rel <= i8::MAX as isize {
                self.emit(0xEB);
                self.emit(rel as u8);
                return;
            }
        }
        // Forward jump or out of rel8 range — use rel32
        self.emit(0xE9);
        self.emit_label_fixup(label);
    }

    /// jcc to label — uses rel8 for backward jumps within ±127 bytes.
    pub fn jcc_label(&mut self, cc: Cc, label: Label) {
        let bound = self.labels[label.0 as usize];
        if bound != LABEL_UNBOUND {
            let target = bound;
            // Backward jump — label already bound, try rel8.
            // rel8 offset = target - (current + 2), where 2 = size of jcc rel8
            let rel = target as isize - (self.code.len() as isize + 2);
            if rel >= i8::MIN as isize && rel <= i8::MAX as isize {
                self.emit(0x70 + cc as u8);
                self.emit(rel as u8);
                return;
            }
        }
        // Forward jump or out of rel8 range — use rel32
        self.emit(0x0F);
        self.emit(0x80 + cc as u8);
        self.emit_label_fixup(label);
    }

    /// jmp r64 (indirect)
    pub fn jmp_reg(&mut self, reg: Reg) {
        self.rex_opt_b(reg);
        self.emit(0xFF);
        self.emit(0xE0 | reg.lo()); // /4
    }

    /// call r64 (indirect)
    pub fn call_reg(&mut self, reg: Reg) {
        self.rex_opt_b(reg);
        self.emit(0xFF);
        self.emit(0xD0 | reg.lo()); // /2
    }

    /// call label
    pub fn call_label(&mut self, label: Label) {
        self.emit(0xE8);
        self.emit_label_fixup(label);
    }

    /// ret
    pub fn ret(&mut self) {
        self.emit(0xC3);
    }

    // -- LEA --

    /// lea r64, [base + disp]
    pub fn lea(&mut self, dst: Reg, base: Reg, disp: i32) {
        self.rex_w(dst, base);
        self.emit(0x8D);
        self.modrm_disp(dst.lo(), base, disp);
    }

    /// lea r32, [base + disp] — 32-bit result, zero-extends to 64-bit.
    /// Combines address truncation and offset addition in one instruction.
    pub fn lea_32(&mut self, dst: Reg, base: Reg, disp: i32) {
        self.rex_opt(dst, base);
        self.emit(0x8D);
        self.modrm_disp(dst.lo(), base, disp);
    }

    /// lea r32, [base32 + index32 * 4]  (32-bit result, auto zero-extends to 64)
    /// lea dst32, [base32 + index32 * (1 << scale_log2)]
    /// scale_log2: 0=*1, 1=*2, 2=*4, 3=*8
    pub fn lea_sib_scaled_32(&mut self, dst: Reg, base: Reg, index: Reg, scale_log2: u8) {
        debug_assert!(scale_log2 <= 3);
        let rex = 0x40 | (dst.hi() << 2) | (index.hi() << 1) | base.hi();
        if rex != 0x40 { self.emit(rex); }
        self.emit(0x8D); // LEA
        let scale_bits = scale_log2 << 6;
        if base.lo() == 5 {
            // RBP/R13 as base: need mod=01 with disp8=0 (mod=00 means [disp32])
            self.emit(0x44 | (dst.lo() << 3)); // mod=01, reg=dst, rm=100(SIB)
            self.emit(scale_bits | (index.lo() << 3) | base.lo());
            self.emit(0x00); // disp8 = 0
        } else {
            self.emit((dst.lo() << 3) | 0x04); // mod=00, reg=dst, rm=100(SIB)
            self.emit(scale_bits | (index.lo() << 3) | base.lo());
        }
    }

    // -- Misc --

    /// ud2 (undefined instruction, for traps)
    pub fn ud2(&mut self) {
        self.emit(0x0F);
        self.emit(0x0B);
    }

    /// nop
    pub fn nop(&mut self) {
        self.emit(0x90);
    }

    /// int3 (debug breakpoint)
    pub fn int3(&mut self) {
        self.emit(0xCC);
    }

    // === Finalization ===

    /// Get the resolved native offset for a label (only valid after bind_label).
    pub fn label_offset(&self, label: Label) -> Option<usize> {
        let off = self.labels[label.0 as usize];
        if off == LABEL_UNBOUND { None } else { Some(off) }
    }

    /// Resolve all label fixups and return the final machine code.
    /// Panics if any label is unbound.
    pub fn finalize(mut self) -> Vec<u8> {
        for fixup in &self.fixups {
            let target = self.labels[fixup.label.0 as usize];
            assert!(target != LABEL_UNBOUND, "unbound label {:?}", fixup.label);
            // rel32 = target - (fixup_offset + 4) because the offset is relative
            // to the end of the instruction (after the 4-byte immediate).
            let rel = (target as i64) - (fixup.offset as i64 + 4);
            let rel32 = rel as i32;
            self.code[fixup.offset..fixup.offset + 4]
                .copy_from_slice(&rel32.to_le_bytes());
        }
        self.code
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mov_ri64_zero() {
        let mut asm = Assembler::new();
        asm.mov_ri64(Reg::RAX, 0);
        // xor eax, eax → 0x31 0xC0
        assert_eq!(&asm.code, &[0x31, 0xC0]);
    }

    #[test]
    fn test_mov_ri64_small() {
        let mut asm = Assembler::new();
        asm.mov_ri64(Reg::RAX, 42);
        // mov eax, 42 → 0xB8, 0x2A, 0x00, 0x00, 0x00
        assert_eq!(&asm.code, &[0xB8, 0x2A, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_label_resolution() {
        let mut asm = Assembler::new();
        let lbl = asm.new_label();
        asm.jmp_label(lbl); // 5 bytes: E9 + 4-byte rel32
        asm.nop();           // 1 byte at offset 5
        asm.bind_label(lbl); // label at offset 6
        let code = asm.finalize();
        // rel32 = 6 - (0 + 4 + 1) = 6 - 5 = 1
        // Wait: fixup offset is 1 (after E9), target is 6
        // rel = 6 - (1 + 4) = 1
        assert_eq!(code[0], 0xE9);
        let rel = i32::from_le_bytes([code[1], code[2], code[3], code[4]]);
        assert_eq!(rel, 1); // skip over the nop
    }

    #[test]
    fn test_push_pop_r15() {
        let mut asm = Assembler::new();
        asm.push(Reg::R15);
        asm.pop(Reg::R15);
        // push r15: 41 57, pop r15: 41 5F
        assert_eq!(&asm.code, &[0x41, 0x57, 0x41, 0x5F]);
    }
}
