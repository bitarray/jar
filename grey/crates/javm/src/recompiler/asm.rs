//! x86-64 assembler for PVM recompiler.
//!
//! Emits native x86-64 machine code with label-based jump resolution.
//! All jumps use 32-bit relative offsets (no short-jump optimization).

/// Instruction buffer: accumulates x86 bytes in a u128 register, then flushes
/// with a single bulk write. Avoids per-byte memory stores.
#[derive(Clone, Copy)]
pub struct InstBuf {
    out: u128,
    length: u32, // in bits
}

impl Default for InstBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl InstBuf {
    #[inline(always)]
    pub fn new() -> Self {
        Self { out: 0, length: 0 }
    }

    #[inline(always)]
    pub fn push(&mut self, byte: u8) {
        self.out |= (byte as u128) << self.length;
        self.length += 8;
    }

    #[inline(always)]
    pub fn push_u32(&mut self, v: u32) {
        self.out |= (v as u128) << self.length;
        self.length += 32;
    }

    #[inline(always)]
    pub fn push_u64(&mut self, v: u64) {
        self.out |= (v as u128) << self.length;
        self.length += 64;
    }

    #[inline(always)]
    pub fn push_i32(&mut self, v: i32) {
        self.push_u32(v as u32);
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        (self.length >> 3) as usize
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
}

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
    B = 2,  // Below (unsigned <)
    AE = 3, // Above or Equal (unsigned >=)
    E = 4,  // Equal
    NE = 5, // Not Equal
    BE = 6, // Below or Equal (unsigned <=)
    A = 7,  // Above (unsigned >)
    S = 8,  // Sign
    NS = 9,
    P = 10,
    NP = 11,
    L = 12,  // Less (signed <)
    GE = 13, // Greater or Equal (signed >=)
    LE = 14, // Less or Equal (signed <=)
    G = 15,  // Greater (signed >)
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

/// Code buffer mode: either Vec-backed (for tests) or mmap-backed (for JIT).
enum CodeBuf {
    /// Heap-allocated via Vec (used by tests and small programs).
    Vec(Vec<u8>),
    /// mmap-backed (PROT_READ|PROT_WRITE). Avoids the copy in NativeCode::new
    /// by writing directly to the buffer that will become executable.
    Mmap { ptr: *mut u8, capacity: usize },
}

/// x86-64 assembler with label support.
///
/// Uses direct pointer writes to the pre-allocated buffer for emission,
/// avoiding per-byte Vec::push overhead (capacity check + len update).
pub struct Assembler {
    code_buf: CodeBuf,
    /// Raw pointer to the start of the code buffer.
    buf: *mut u8,
    write_pos: usize,
    capacity: usize,
    /// Label ID → bound offset+1 as u32 (0 = unbound). Uses u32 to halve
    /// memory vs usize (native code always fits in 4GB).
    /// Pre-sized via `vec![0u32; capacity]` which uses calloc (zero-page COW).
    labels: Vec<u32>,
    /// Number of labels allocated via new_label/bulk_create_labels.
    /// The Vec is pre-sized but labels_len tracks the logical length.
    labels_len: usize,
    fixups: Vec<Fixup>,
}

/// Unbound label sentinel. We use 0 so that bulk label allocation can use
/// zeroed memory (calloc / zero-page COW) instead of writing 0xFF to every byte.
/// Bound labels store `native_offset + 1` to avoid collision with the sentinel.
const LABEL_UNBOUND: u32 = 0;

impl Default for Assembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Assembler {
    pub fn new() -> Self {
        let mut code = Vec::with_capacity(4096);
        let buf = code.as_mut_ptr();
        let capacity = code.capacity();
        Self {
            code_buf: CodeBuf::Vec(code),
            buf,
            write_pos: 0,
            capacity,
            labels: Vec::new(),
            labels_len: 0,
            fixups: Vec::new(),
        }
    }

    /// Create with pre-allocated capacity for code and labels.
    /// Uses Vec-backed buffer (for tests or when mmap is not needed).
    pub fn with_capacity(code_capacity: usize, label_capacity: usize) -> Self {
        let mut code = Vec::with_capacity(code_capacity);
        let buf = code.as_mut_ptr();
        let capacity = code.capacity();
        Self {
            code_buf: CodeBuf::Vec(code),
            buf,
            write_pos: 0,
            capacity,
            // vec![0; n] uses calloc — zero pages via COW, no page faults for untouched entries
            labels: vec![0u32; label_capacity],
            labels_len: 0,
            fixups: Vec::with_capacity(2048),
        }
    }

    /// Create with an mmap-backed code buffer. Code is written directly to the
    /// mmap region during compilation. After finalize_mmap(), the buffer is
    /// mprotected to PROT_READ|PROT_EXEC — no copy needed.
    pub fn with_mmap(code_capacity: usize, label_capacity: usize) -> Result<Self, String> {
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                code_capacity,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED || ptr.is_null() {
            return Err("mmap failed for assembler code buffer".into());
        }
        let ptr = ptr as *mut u8;
        Ok(Self {
            code_buf: CodeBuf::Mmap {
                ptr,
                capacity: code_capacity,
            },
            buf: ptr,
            write_pos: 0,
            capacity: code_capacity,
            labels: vec![0u32; label_capacity],
            labels_len: 0,
            // Fixups are far fewer than labels — typically ~2K for large programs
            // (one per forward branch + one per OOG stub jcc). Over-allocating to
            // label_capacity wastes ~1.5MB for ecrecover.
            fixups: Vec::with_capacity(2048),
        })
    }

    /// Ensure at least `additional` bytes of capacity remain.
    /// Called before emitting large sequences. Most individual instructions
    /// need at most ~32 bytes, so this is rarely needed mid-compilation.
    #[cold]
    fn grow(&mut self, additional: usize) {
        match &mut self.code_buf {
            CodeBuf::Vec(code) => {
                unsafe {
                    code.set_len(self.write_pos);
                }
                code.reserve(additional);
                self.buf = code.as_mut_ptr();
                self.capacity = code.capacity();
                unsafe {
                    code.set_len(0);
                }
            }
            CodeBuf::Mmap { ptr, capacity } => {
                // For mmap buffers, mremap to a larger size
                let new_cap = (*capacity + additional).next_power_of_two();
                let new_ptr = unsafe {
                    libc::mremap(
                        *ptr as *mut libc::c_void,
                        *capacity,
                        new_cap,
                        libc::MREMAP_MAYMOVE,
                    )
                };
                if new_ptr == libc::MAP_FAILED {
                    panic!("mremap failed: need {} bytes", new_cap);
                }
                *ptr = new_ptr as *mut u8;
                *capacity = new_cap;
                self.buf = *ptr;
                self.capacity = new_cap;
            }
        }
    }

    /// Check capacity and grow if needed. Inlined for the fast path (no grow).
    #[inline(always)]
    pub fn ensure_capacity(&mut self, n: usize) {
        if self.write_pos + n > self.capacity {
            self.grow(n);
        }
    }

    /// Allocate a new label.
    pub fn new_label(&mut self) -> Label {
        let id = self.labels_len as u32;
        self.labels_len += 1;
        // Grow if needed (rare — labels Vec is pre-sized in with_capacity/with_mmap)
        if self.labels_len > self.labels.len() {
            self.labels.push(LABEL_UNBOUND);
        }
        Label(id)
    }

    /// Current number of labels allocated.
    pub fn labels_len(&self) -> usize {
        self.labels_len
    }

    /// Bulk-allocate `count` unbound labels. The labels Vec is already pre-sized
    /// via calloc (zero pages). This just advances the logical length counter.
    pub fn bulk_create_labels(&mut self, count: usize) {
        self.labels_len += count;
        // Grow if pre-sized Vec wasn't large enough (shouldn't happen normally)
        if self.labels_len > self.labels.len() {
            self.labels.resize(self.labels_len, LABEL_UNBOUND);
        }
    }

    /// Bind a label to the current write position.
    pub fn bind_label(&mut self, label: Label) {
        self.labels[label.0 as usize] = (self.write_pos + 1) as u32; // +1: 0 is LABEL_UNBOUND
    }

    /// Current code offset (write position).
    pub fn offset(&self) -> usize {
        self.write_pos
    }

    /// Patch an i32 value at a previously recorded offset.
    pub fn patch_i32(&mut self, offset: usize, value: i32) {
        debug_assert!(offset + 4 <= self.write_pos);
        unsafe {
            std::ptr::copy_nonoverlapping(value.to_le_bytes().as_ptr(), self.buf.add(offset), 4);
        }
    }

    // === Raw byte emission ===
    // All emission writes directly to the buffer via raw pointer,
    // bypassing Vec::push's capacity check and len update.

    #[inline(always)]
    fn emit(&mut self, b: u8) {
        debug_assert!(self.write_pos < self.capacity);
        unsafe {
            *self.buf.add(self.write_pos) = b;
        }
        self.write_pos += 1;
    }

    /// Emit 3 bytes at once.
    #[inline(always)]
    fn emit3(&mut self, a: u8, b: u8, c: u8) {
        debug_assert!(self.write_pos + 3 <= self.capacity);
        unsafe {
            let p = self.buf.add(self.write_pos);
            *p = a;
            *p.add(1) = b;
            *p.add(2) = c;
        }
        self.write_pos += 3;
    }

    /// Flush an InstBuf to the code buffer in one bulk write.
    #[inline(always)]
    fn flush_instbuf(&mut self, ib: InstBuf) {
        let len = ib.len();
        debug_assert!(self.write_pos + len <= self.capacity);
        unsafe {
            let p = self.buf.add(self.write_pos);
            // Always write both halves — the second write may go past the
            // instruction boundary but the buffer has ample capacity (ensured
            // by ensure_capacity(512)). Eliminates a branch per emission.
            std::ptr::write_unaligned(p as *mut u64, ib.out as u64);
            std::ptr::write_unaligned(p.add(8) as *mut u64, (ib.out >> 64) as u64);
        }
        self.write_pos += len;
    }

    #[inline(always)]
    fn emit_u32(&mut self, v: u32) {
        debug_assert!(self.write_pos + 4 <= self.capacity);
        unsafe {
            std::ptr::write_unaligned(self.buf.add(self.write_pos) as *mut u32, v.to_le());
        }
        self.write_pos += 4;
    }

    #[inline(always)]
    #[allow(dead_code)]
    fn emit_u64(&mut self, v: u64) {
        debug_assert!(self.write_pos + 8 <= self.capacity);
        unsafe {
            std::ptr::write_unaligned(self.buf.add(self.write_pos) as *mut u64, v.to_le());
        }
        self.write_pos += 8;
    }

    #[inline(always)]
    fn emit_i32(&mut self, v: i32) {
        debug_assert!(self.write_pos + 4 <= self.capacity);
        unsafe {
            std::ptr::write_unaligned(
                self.buf.add(self.write_pos) as *mut u32,
                v.to_le_bytes().as_ptr().cast::<u32>().read(),
            );
        }
        self.write_pos += 4;
    }

    /// Emit a label reference (4-byte rel32). For backward references (label
    /// already bound), resolves immediately without creating a fixup entry.
    /// For forward references, emits a placeholder and records a fixup.
    fn emit_label_fixup(&mut self, label: Label) {
        let bound = self.labels[label.0 as usize];
        if bound != LABEL_UNBOUND {
            // Backward reference — resolve immediately, no fixup needed.
            // rel32 = target - (current_offset + 4). Stored value is offset+1.
            let target = (bound - 1) as i64;
            let rel = target - (self.write_pos as i64 + 4);
            self.emit_i32(rel as i32);
        } else {
            // Forward reference — defer to finalization.
            let offset = self.write_pos;
            self.fixups.push(Fixup { offset, label });
            self.emit_u32(0); // placeholder
        }
    }

    // === REX prefix helpers ===

    /// REX prefix for 64-bit reg-reg operations.
    #[allow(dead_code)]
    fn rex_w(&mut self, reg: Reg, rm: Reg) {
        self.emit(0x48 | (reg.hi() << 2) | rm.hi());
    }

    /// REX.W prefix for single-register operations.
    fn rex_w_b(&mut self, rm: Reg) {
        self.emit(0x48 | rm.hi());
    }

    /// Optional REX prefix for 32-bit ops (only if extended registers).
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    fn modrm_rr(&mut self, reg: Reg, rm: Reg) {
        self.emit(0xC0 | (reg.lo() << 3) | rm.lo());
    }

    /// ModR/M (+ optional SIB) + displacement for [base + disp] addressing.
    /// Pushes into an InstBuf instead of emitting directly.
    #[inline(always)]
    fn modrm_disp_ib(ib: &mut InstBuf, reg: u8, base: Reg, disp: i32) {
        let bl = base.lo();
        let needs_sib = bl == 4;

        if disp == 0 && bl != 5 {
            if needs_sib {
                ib.push((reg << 3) | 4);
                ib.push(0x24);
            } else {
                ib.push((reg << 3) | bl);
            }
        } else if (-128..=127).contains(&disp) {
            if needs_sib {
                ib.push(0x40 | (reg << 3) | 4);
                ib.push(0x24);
            } else {
                ib.push(0x40 | (reg << 3) | bl);
            }
            ib.push(disp as u8);
        } else {
            if needs_sib {
                ib.push(0x80 | (reg << 3) | 4);
                ib.push(0x24);
            } else {
                ib.push(0x80 | (reg << 3) | bl);
            }
            ib.push_i32(disp);
        }
    }

    /// Legacy wrapper — delegates to InstBuf-based version.
    #[allow(dead_code)]
    fn modrm_disp(&mut self, reg: u8, base: Reg, disp: i32) {
        let mut ib = InstBuf::new();
        Self::modrm_disp_ib(&mut ib, reg, base, disp);
        self.flush_instbuf(ib);
    }

    /// ModR/M + SIB for [base + index] addressing, into InstBuf.
    #[inline(always)]
    fn modrm_sib_base_index_ib(ib: &mut InstBuf, reg: u8, base: Reg, index: Reg) {
        if base.lo() == 5 {
            ib.push(0x44 | (reg << 3));
            ib.push((index.lo() << 3) | base.lo());
            ib.push(0);
        } else {
            ib.push((reg << 3) | 4);
            ib.push((index.lo() << 3) | base.lo());
        }
    }

    /// Emit ModR/M + displacement for [base + disp] with always-disp32 encoding.
    /// Used when the immediate after the displacement must be at a fixed offset
    /// (e.g., for patch-based gas metering where the imm32 is written later).
    fn modrm_disp32(&mut self, reg: u8, base: Reg, disp: i32) {
        let mut ib = InstBuf::new();
        if base.lo() == 4 {
            ib.push(0x80 | (reg << 3) | 4);
            ib.push(0x24);
        } else {
            ib.push(0x80 | (reg << 3) | base.lo());
        }
        ib.push_i32(disp);
        self.flush_instbuf(ib);
    }

    // === Instruction emission ===

    // -- MOV --

    /// mov r64, r64
    #[inline(always)]
    pub fn mov_rr(&mut self, dst: Reg, src: Reg) {
        if dst == src {
            return;
        }
        self.emit3(
            0x48 | (src.hi() << 2) | dst.hi(),
            0x89,
            0xC0 | (src.lo() << 3) | dst.lo(),
        );
    }

    /// mov r64, imm64
    #[inline(always)]
    pub fn mov_ri64(&mut self, dst: Reg, imm: u64) {
        let mut ib = InstBuf::new();
        if imm == 0 {
            // xor r32, r32 (clears full r64)
            let r = dst.hi();
            if r != 0 {
                ib.push(0x40 | (r << 2) | r);
            }
            ib.push(0x31);
            ib.push(0xC0 | (dst.lo() << 3) | dst.lo());
        } else if imm <= u32::MAX as u64 {
            // mov r32, imm32 (zero-extends to 64)
            if dst.needs_rex() {
                ib.push(0x40 | dst.hi());
            }
            ib.push(0xB8 + dst.lo());
            ib.push_u32(imm as u32);
        } else if imm as i64 >= i32::MIN as i64 && imm as i64 <= i32::MAX as i64 {
            // mov r64, sign-extended imm32
            ib.push(0x48 | dst.hi());
            ib.push(0xC7);
            ib.push(0xC0 | dst.lo());
            ib.push_i32(imm as i32);
        } else {
            // mov r64, imm64
            ib.push(0x48 | dst.hi());
            ib.push(0xB8 + dst.lo());
            ib.push_u64(imm);
        }
        self.flush_instbuf(ib);
    }

    /// mov r32, imm32 (zero-extends to 64-bit)
    #[inline(always)]
    pub fn mov_ri32(&mut self, dst: Reg, imm: u32) {
        let mut ib = InstBuf::new();
        if dst.needs_rex() {
            ib.push(0x40 | dst.hi());
        }
        ib.push(0xB8 + dst.lo());
        ib.push_u32(imm);
        self.flush_instbuf(ib);
    }

    /// mov r32, [base + disp] — zero-extending 32-bit load
    #[inline(always)]
    pub fn mov_load32(&mut self, dst: Reg, base: Reg, disp: i32) {
        let mut ib = InstBuf::new();
        let r = dst.hi();
        let b = base.hi();
        if r != 0 || b != 0 {
            ib.push(0x40 | (r << 2) | b);
        }
        ib.push(0x8B);
        Self::modrm_disp_ib(&mut ib, dst.lo(), base, disp);
        self.flush_instbuf(ib);
    }

    /// mov r64, [base + disp]
    #[inline(always)]
    pub fn mov_load64(&mut self, dst: Reg, base: Reg, disp: i32) {
        let mut ib = InstBuf::new();
        ib.push(0x48 | (dst.hi() << 2) | base.hi());
        ib.push(0x8B);
        Self::modrm_disp_ib(&mut ib, dst.lo(), base, disp);
        self.flush_instbuf(ib);
    }

    /// movsxd r64, dword [base + index*4] — sign-extending load with SIB scale=4
    pub fn movsxd_load_sib4(&mut self, dst: Reg, base: Reg, index: Reg) {
        let mut ib = InstBuf::new();
        ib.push(0x48 | (dst.hi() << 2) | (index.hi() << 1) | base.hi());
        ib.push(0x63);
        ib.push((dst.lo() << 3) | 4);
        ib.push(0x80 | (index.lo() << 3) | base.lo());
        self.flush_instbuf(ib);
    }

    /// mov dword [base + disp], r32 — 32-bit store
    #[inline(always)]
    pub fn mov_store32(&mut self, base: Reg, disp: i32, src: Reg) {
        let mut ib = InstBuf::new();
        let r = src.hi();
        let b = base.hi();
        if r != 0 || b != 0 {
            ib.push(0x40 | (r << 2) | b);
        }
        ib.push(0x89);
        Self::modrm_disp_ib(&mut ib, src.lo(), base, disp);
        self.flush_instbuf(ib);
    }

    /// mov [base + disp], r64
    #[inline(always)]
    pub fn mov_store64(&mut self, base: Reg, disp: i32, src: Reg) {
        let mut ib = InstBuf::new();
        ib.push(0x48 | (src.hi() << 2) | base.hi());
        ib.push(0x89);
        Self::modrm_disp_ib(&mut ib, src.lo(), base, disp);
        self.flush_instbuf(ib);
    }

    /// mov dword [base + disp], imm32
    #[inline(always)]
    pub fn mov_store32_imm(&mut self, base: Reg, disp: i32, imm: i32) {
        let mut ib = InstBuf::new();
        if base.needs_rex() {
            ib.push(0x40 | base.hi());
        }
        ib.push(0xC7);
        Self::modrm_disp_ib(&mut ib, 0, base, disp);
        ib.push_i32(imm);
        self.flush_instbuf(ib);
    }

    /// mov qword [base + disp], sign-extended imm32
    pub fn mov_store64_imm(&mut self, base: Reg, disp: i32, imm: i32) {
        let mut ib = InstBuf::new();
        ib.push(0x48 | base.hi());
        ib.push(0xC7);
        Self::modrm_disp_ib(&mut ib, 0, base, disp);
        ib.push_i32(imm);
        self.flush_instbuf(ib);
    }

    // -- SIB-based memory access [base + index] --

    /// Emit ModR/M + SIB for [base + index] addressing (scale=1, no displacement).
    /// Special case: base=RBP/R13 requires mod=01 with disp8=0.
    /// Legacy wrapper — used by methods not yet converted to InstBuf.
    #[allow(dead_code)]
    fn modrm_sib_base_index(&mut self, reg: u8, base: Reg, index: Reg) {
        let mut ib = InstBuf::new();
        Self::modrm_sib_base_index_ib(&mut ib, reg, base, index);
        self.flush_instbuf(ib);
    }

    /// movzx r64, byte [base + index] — zero-extending u8 load
    pub fn movzx_load8_sib(&mut self, dst: Reg, base: Reg, index: Reg) {
        let mut ib = InstBuf::new();
        ib.push(0x48 | (dst.hi() << 2) | (index.hi() << 1) | base.hi());
        ib.push(0x0F);
        ib.push(0xB6);
        Self::modrm_sib_base_index_ib(&mut ib, dst.lo(), base, index);
        self.flush_instbuf(ib);
    }

    /// movzx r32, word [base + index] — zero-extending u16 load
    pub fn movzx_load16_sib(&mut self, dst: Reg, base: Reg, index: Reg) {
        let mut ib = InstBuf::new();
        let rex = 0x40 | (dst.hi() << 2) | (index.hi() << 1) | base.hi();
        if rex != 0x40 {
            ib.push(rex);
        }
        ib.push(0x0F);
        ib.push(0xB7);
        Self::modrm_sib_base_index_ib(&mut ib, dst.lo(), base, index);
        self.flush_instbuf(ib);
    }

    /// mov r32, dword [base + index] — zero-extending u32 load
    pub fn mov_load32_sib(&mut self, dst: Reg, base: Reg, index: Reg) {
        let mut ib = InstBuf::new();
        let rex = 0x40 | (dst.hi() << 2) | (index.hi() << 1) | base.hi();
        if rex != 0x40 {
            ib.push(rex);
        }
        ib.push(0x8B);
        Self::modrm_sib_base_index_ib(&mut ib, dst.lo(), base, index);
        self.flush_instbuf(ib);
    }

    /// mov r64, qword [base + index]
    pub fn mov_load64_sib(&mut self, dst: Reg, base: Reg, index: Reg) {
        let mut ib = InstBuf::new();
        ib.push(0x48 | (dst.hi() << 2) | (index.hi() << 1) | base.hi());
        ib.push(0x8B);
        Self::modrm_sib_base_index_ib(&mut ib, dst.lo(), base, index);
        self.flush_instbuf(ib);
    }

    /// mov byte [base + index], r8
    pub fn mov_store8_sib(&mut self, base: Reg, index: Reg, src: Reg) {
        let mut ib = InstBuf::new();
        ib.push(0x40 | (src.hi() << 2) | (index.hi() << 1) | base.hi());
        ib.push(0x88);
        Self::modrm_sib_base_index_ib(&mut ib, src.lo(), base, index);
        self.flush_instbuf(ib);
    }

    /// mov word [base + index], r16
    pub fn mov_store16_sib(&mut self, base: Reg, index: Reg, src: Reg) {
        let mut ib = InstBuf::new();
        ib.push(0x66);
        let rex = 0x40 | (src.hi() << 2) | (index.hi() << 1) | base.hi();
        if rex != 0x40 {
            ib.push(rex);
        }
        ib.push(0x89);
        Self::modrm_sib_base_index_ib(&mut ib, src.lo(), base, index);
        self.flush_instbuf(ib);
    }

    /// mov dword [base + index], r32
    pub fn mov_store32_sib(&mut self, base: Reg, index: Reg, src: Reg) {
        let mut ib = InstBuf::new();
        let rex = 0x40 | (src.hi() << 2) | (index.hi() << 1) | base.hi();
        if rex != 0x40 {
            ib.push(rex);
        }
        ib.push(0x89);
        Self::modrm_sib_base_index_ib(&mut ib, src.lo(), base, index);
        self.flush_instbuf(ib);
    }

    /// mov qword [base + index], r64
    pub fn mov_store64_sib(&mut self, base: Reg, index: Reg, src: Reg) {
        let mut ib = InstBuf::new();
        ib.push(0x48 | (src.hi() << 2) | (index.hi() << 1) | base.hi());
        ib.push(0x89);
        Self::modrm_sib_base_index_ib(&mut ib, src.lo(), base, index);
        self.flush_instbuf(ib);
    }

    /// mov dword [base + index], imm32
    pub fn mov_store32_sib_imm(&mut self, base: Reg, index: Reg, imm: i32) {
        let mut ib = InstBuf::new();
        let rex = 0x40 | (index.hi() << 1) | base.hi();
        if rex != 0x40 {
            ib.push(rex);
        }
        ib.push(0xC7);
        Self::modrm_sib_base_index_ib(&mut ib, 0, base, index);
        ib.push_i32(imm);
        self.flush_instbuf(ib);
    }

    /// mov qword [base + index], sign-extended imm32
    pub fn mov_store64_sib_imm(&mut self, base: Reg, index: Reg, imm: i32) {
        let mut ib = InstBuf::new();
        ib.push(0x48 | (index.hi() << 1) | base.hi());
        ib.push(0xC7);
        Self::modrm_sib_base_index_ib(&mut ib, 0, base, index);
        ib.push_i32(imm);
        self.flush_instbuf(ib);
    }

    /// mov byte [base + index], imm8
    pub fn mov_store8_sib_imm(&mut self, base: Reg, index: Reg, imm: u8) {
        let mut ib = InstBuf::new();
        ib.push(0x40 | (index.hi() << 1) | base.hi());
        ib.push(0xC6);
        Self::modrm_sib_base_index_ib(&mut ib, 0, base, index);
        ib.push(imm);
        self.flush_instbuf(ib);
    }

    /// mov word [base + index], imm16
    pub fn mov_store16_sib_imm(&mut self, base: Reg, index: Reg, imm: u16) {
        let mut ib = InstBuf::new();
        ib.push(0x66);
        let rex = 0x40 | (index.hi() << 1) | base.hi();
        if rex != 0x40 {
            ib.push(rex);
        }
        ib.push(0xC7);
        Self::modrm_sib_base_index_ib(&mut ib, 0, base, index);
        ib.push(imm as u8);
        ib.push((imm >> 8) as u8);
        self.flush_instbuf(ib);
    }

    /// add r64, qword [base + disp32]
    pub fn add_r64_mem(&mut self, dst: Reg, base: Reg, disp: i32) {
        let mut ib = InstBuf::new();
        ib.push(0x48 | (dst.hi() << 2) | base.hi());
        ib.push(0x03);
        Self::modrm_disp_ib(&mut ib, dst.lo(), base, disp);
        self.flush_instbuf(ib);
    }

    /// movzx r64, byte [rax] (simple deref, no SIB needed) — for perm table lookup
    pub fn movzx_load8_deref(&mut self, dst: Reg, base: Reg) {
        let mut ib = InstBuf::new();
        ib.push(0x48 | (dst.hi() << 2) | base.hi());
        ib.push(0x0F);
        ib.push(0xB6);
        if base.lo() == 5 {
            ib.push((dst.lo() << 3) | base.lo() | 0x40);
            ib.push(0);
        } else if base.lo() == 4 {
            ib.push((dst.lo() << 3) | 4);
            ib.push(0x24);
        } else {
            ib.push((dst.lo() << 3) | base.lo());
        }
        self.flush_instbuf(ib);
    }

    /// cmp byte [base + index + disp32], imm8 — compare memory byte with SIB+displacement
    pub fn cmp_byte_sib_disp32(&mut self, base: Reg, index: Reg, disp: i32, imm: u8) {
        let mut ib = InstBuf::new();
        let rex = 0x40 | (index.hi() << 1) | base.hi();
        if rex != 0x40 {
            ib.push(rex);
        }
        ib.push(0x80);
        ib.push(0xBC); // mod=10, reg=/7(CMP), rm=100(SIB)
        ib.push((index.lo() << 3) | base.lo());
        ib.push_i32(disp);
        ib.push(imm);
        self.flush_instbuf(ib);
    }

    /// cmp byte [reg], imm8 — compare memory byte with immediate
    pub fn cmp_byte_deref_imm(&mut self, base: Reg, imm: u8) {
        let mut ib = InstBuf::new();
        if base.needs_rex() {
            ib.push(0x41 | base.hi());
        }
        ib.push(0x80);
        if base.lo() == 5 {
            ib.push(0x78 | base.lo());
            ib.push(0);
        } else if base.lo() == 4 {
            ib.push(0x38 | 4);
            ib.push(0x24);
        } else {
            ib.push(0x38 | base.lo());
        }
        ib.push(imm);
        self.flush_instbuf(ib);
    }

    // -- ALU reg,reg (64-bit) --

    fn alu_rr64(&mut self, op: u8, dst: Reg, src: Reg) {
        let mut ib = InstBuf::new();
        ib.push(0x48 | (src.hi() << 2) | dst.hi());
        ib.push(op);
        ib.push(0xC0 | (src.lo() << 3) | dst.lo());
        self.flush_instbuf(ib);
    }

    fn alu_rr32(&mut self, op: u8, dst: Reg, src: Reg) {
        let r = src.hi();
        let b = dst.hi();
        if r != 0 || b != 0 {
            let mut ib = InstBuf::new();
            ib.push(0x40 | (r << 2) | b);
            ib.push(op);
            ib.push(0xC0 | (src.lo() << 3) | dst.lo());
            self.flush_instbuf(ib);
        } else {
            let mut ib = InstBuf::new();
            ib.push(op);
            ib.push(0xC0 | (src.lo() << 3) | dst.lo());
            self.flush_instbuf(ib);
        }
    }

    #[inline(always)]
    pub fn add_rr(&mut self, dst: Reg, src: Reg) {
        self.alu_rr64(0x01, dst, src);
    }
    #[inline(always)]
    pub fn sub_rr(&mut self, dst: Reg, src: Reg) {
        self.alu_rr64(0x29, dst, src);
    }
    #[inline(always)]
    pub fn and_rr(&mut self, dst: Reg, src: Reg) {
        self.alu_rr64(0x21, dst, src);
    }
    #[inline(always)]
    pub fn or_rr(&mut self, dst: Reg, src: Reg) {
        self.alu_rr64(0x09, dst, src);
    }
    #[inline(always)]
    pub fn xor_rr(&mut self, dst: Reg, src: Reg) {
        self.alu_rr64(0x31, dst, src);
    }
    #[inline(always)]
    pub fn cmp_rr(&mut self, a: Reg, b: Reg) {
        self.alu_rr64(0x39, a, b);
    }
    #[inline(always)]
    pub fn test_rr(&mut self, a: Reg, b: Reg) {
        self.alu_rr64(0x85, a, b);
    }

    #[inline(always)]
    pub fn add_rr32(&mut self, dst: Reg, src: Reg) {
        self.alu_rr32(0x01, dst, src);
    }
    #[inline(always)]
    pub fn sub_rr32(&mut self, dst: Reg, src: Reg) {
        self.alu_rr32(0x29, dst, src);
    }

    // -- ALU reg,imm (64-bit) --
    // Uses imm8 (opcode 0x83) when immediate fits in -128..127, saving 3 bytes.

    #[inline(always)]
    fn alu_ri64(&mut self, ext: u8, dst: Reg, imm: i32) {
        let mut ib = InstBuf::new();
        ib.push(0x48 | dst.hi());
        if (-128..=127).contains(&imm) {
            ib.push(0x83);
            ib.push(0xC0 | (ext << 3) | dst.lo());
            ib.push(imm as u8);
        } else {
            ib.push(0x81);
            ib.push(0xC0 | (ext << 3) | dst.lo());
            ib.push_i32(imm);
        }
        self.flush_instbuf(ib);
    }

    #[inline(always)]
    fn alu_ri32(&mut self, ext: u8, dst: Reg, imm: i32) {
        let mut ib = InstBuf::new();
        if dst.needs_rex() {
            ib.push(0x40 | dst.hi());
        }
        if (-128..=127).contains(&imm) {
            ib.push(0x83);
            ib.push(0xC0 | (ext << 3) | dst.lo());
            ib.push(imm as u8);
        } else {
            ib.push(0x81);
            ib.push(0xC0 | (ext << 3) | dst.lo());
            ib.push_i32(imm);
        }
        self.flush_instbuf(ib);
    }

    #[inline(always)]
    pub fn add_ri(&mut self, dst: Reg, imm: i32) {
        self.alu_ri64(0, dst, imm);
    }
    #[inline(always)]
    pub fn sub_ri(&mut self, dst: Reg, imm: i32) {
        self.alu_ri64(5, dst, imm);
    }
    #[inline(always)]
    pub fn and_ri(&mut self, dst: Reg, imm: i32) {
        self.alu_ri64(4, dst, imm);
    }
    #[inline(always)]
    pub fn or_ri(&mut self, dst: Reg, imm: i32) {
        self.alu_ri64(1, dst, imm);
    }
    #[inline(always)]
    pub fn xor_ri(&mut self, dst: Reg, imm: i32) {
        self.alu_ri64(6, dst, imm);
    }
    #[inline(always)]
    pub fn cmp_ri(&mut self, a: Reg, imm: i32) {
        self.alu_ri64(7, a, imm);
    }

    #[inline(always)]
    pub fn add_ri32(&mut self, dst: Reg, imm: i32) {
        self.alu_ri32(0, dst, imm);
    }
    #[inline(always)]
    pub fn sub_ri32(&mut self, dst: Reg, imm: i32) {
        self.alu_ri32(5, dst, imm);
    }
    #[inline(always)]
    pub fn cmp_ri32(&mut self, a: Reg, imm: i32) {
        self.alu_ri32(7, a, imm);
    }

    /// cmp dword [base + disp], imm32
    pub fn cmp_mem32_imm(&mut self, base: Reg, disp: i32, imm: i32) {
        let mut ib = InstBuf::new();
        if base.hi() != 0 {
            ib.push(0x41);
        }
        ib.push(0x81);
        Self::modrm_disp_ib(&mut ib, 7, base, disp);
        ib.push_i32(imm);
        self.flush_instbuf(ib);
    }

    /// cmp dword [base + disp], reg32  (sets flags: mem vs reg)
    pub fn cmp_mem32_r(&mut self, base: Reg, disp: i32, src: Reg) {
        let mut ib = InstBuf::new();
        if base.hi() != 0 || src.hi() != 0 {
            ib.push(0x40 | src.hi() << 2 | base.hi());
        }
        ib.push(0x39);
        Self::modrm_disp_ib(&mut ib, src.lo(), base, disp);
        self.flush_instbuf(ib);
    }

    /// sub qword [base + disp32], sign-extended imm32.
    /// Always uses disp32 encoding (the imm32 is patched after emission for gas metering).
    pub fn sub_mem64_imm32(&mut self, base: Reg, disp: i32, imm: i32) {
        // NOTE: Cannot use InstBuf here — caller reads offset() for gas patching.
        // The offset must be at the exact position of the imm32 field.
        self.rex_w_b(base);
        self.emit(0x81);
        self.modrm_disp32(5, base, disp);
        self.emit_i32(imm);
    }

    /// add qword [base + disp32], imm32
    pub fn add_mem64_imm32(&mut self, base: Reg, disp: i32, imm: i32) {
        // Same as sub_mem64_imm32 — offset() must be accurate for patching.
        self.rex_w_b(base);
        self.emit(0x81);
        self.modrm_disp32(0, base, disp);
        self.emit_i32(imm);
    }

    // -- IMUL --

    /// imul r64, r64
    pub fn imul_rr(&mut self, dst: Reg, src: Reg) {
        let mut ib = InstBuf::new();
        ib.push(0x48 | (dst.hi() << 2) | src.hi());
        ib.push(0x0F);
        ib.push(0xAF);
        ib.push(0xC0 | (dst.lo() << 3) | src.lo());
        self.flush_instbuf(ib);
    }

    /// imul r32, r32
    pub fn imul_rr32(&mut self, dst: Reg, src: Reg) {
        let mut ib = InstBuf::new();
        let r = dst.hi();
        let b = src.hi();
        if r != 0 || b != 0 {
            ib.push(0x40 | (r << 2) | b);
        }
        ib.push(0x0F);
        ib.push(0xAF);
        ib.push(0xC0 | (dst.lo() << 3) | src.lo());
        self.flush_instbuf(ib);
    }

    /// imul r64, r64, imm32
    pub fn imul_rri(&mut self, dst: Reg, src: Reg, imm: i32) {
        let mut ib = InstBuf::new();
        ib.push(0x48 | (dst.hi() << 2) | src.hi());
        ib.push(0x69);
        ib.push(0xC0 | (dst.lo() << 3) | src.lo());
        ib.push_i32(imm);
        self.flush_instbuf(ib);
    }

    /// imul r32, r32, imm32
    pub fn imul_rri32(&mut self, dst: Reg, src: Reg, imm: i32) {
        let mut ib = InstBuf::new();
        let r = dst.hi();
        let b = src.hi();
        if r != 0 || b != 0 {
            ib.push(0x40 | (r << 2) | b);
        }
        ib.push(0x69);
        ib.push(0xC0 | (dst.lo() << 3) | src.lo());
        ib.push_i32(imm);
        self.flush_instbuf(ib);
    }

    // -- MUL/IMUL widening (RDX:RAX = RAX * src) --

    /// mul r64 (unsigned RDX:RAX = RAX * src)
    pub fn mul_rdx_rax(&mut self, src: Reg) {
        self.emit3(0x48 | src.hi(), 0xF7, 0xE0 | src.lo());
    }

    /// imul r64 (signed RDX:RAX = RAX * src)
    pub fn imul_rdx_rax(&mut self, src: Reg) {
        self.emit3(0x48 | src.hi(), 0xF7, 0xE8 | src.lo());
    }

    // -- DIV/IDIV --

    /// div r64 (unsigned RAX = RDX:RAX / src, RDX = remainder)
    pub fn div64(&mut self, src: Reg) {
        self.emit3(0x48 | src.hi(), 0xF7, 0xF0 | src.lo());
    }

    /// idiv r64 (signed)
    pub fn idiv64(&mut self, src: Reg) {
        self.emit3(0x48 | src.hi(), 0xF7, 0xF8 | src.lo());
    }

    /// div r32
    pub fn div32(&mut self, src: Reg) {
        if src.needs_rex() {
            self.emit3(0x41, 0xF7, 0xF0 | src.lo());
        } else {
            let mut ib = InstBuf::new();
            ib.push(0xF7);
            ib.push(0xF0 | src.lo());
            self.flush_instbuf(ib);
        }
    }

    /// idiv r32
    pub fn idiv32(&mut self, src: Reg) {
        if src.needs_rex() {
            self.emit3(0x41, 0xF7, 0xF8 | src.lo());
        } else {
            let mut ib = InstBuf::new();
            ib.push(0xF7);
            ib.push(0xF8 | src.lo());
            self.flush_instbuf(ib);
        }
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
        self.emit3(0x48 | dst.hi(), 0xFF, 0xC0 | dst.lo());
    }

    /// dec r64
    pub fn dec64(&mut self, dst: Reg) {
        self.emit3(0x48 | dst.hi(), 0xFF, 0xC8 | dst.lo());
    }

    // -- NEG/NOT --

    /// neg r64
    pub fn neg64(&mut self, dst: Reg) {
        self.emit3(0x48 | dst.hi(), 0xF7, 0xD8 | dst.lo());
    }

    pub fn neg32(&mut self, dst: Reg) {
        if dst.needs_rex() {
            self.emit3(0x41, 0xF7, 0xD8 | dst.lo());
        } else {
            let mut ib = InstBuf::new();
            ib.push(0xF7);
            ib.push(0xD8 | dst.lo());
            self.flush_instbuf(ib);
        }
    }

    /// not r64
    pub fn not64(&mut self, dst: Reg) {
        self.emit3(0x48 | dst.hi(), 0xF7, 0xD0 | dst.lo());
    }

    // -- Shifts --

    fn shift_ri64(&mut self, ext: u8, dst: Reg, imm: u8) {
        let mut ib = InstBuf::new();
        ib.push(0x48 | dst.hi());
        ib.push(0xC1);
        ib.push(0xC0 | (ext << 3) | dst.lo());
        ib.push(imm);
        self.flush_instbuf(ib);
    }

    pub fn shift_cl64(&mut self, ext: u8, dst: Reg) {
        let mut ib = InstBuf::new();
        ib.push(0x48 | dst.hi());
        ib.push(0xD3);
        ib.push(0xC0 | (ext << 3) | dst.lo());
        self.flush_instbuf(ib);
    }

    fn shift_ri32(&mut self, ext: u8, dst: Reg, imm: u8) {
        let mut ib = InstBuf::new();
        if dst.needs_rex() {
            ib.push(0x40 | dst.hi());
        }
        ib.push(0xC1);
        ib.push(0xC0 | (ext << 3) | dst.lo());
        ib.push(imm);
        self.flush_instbuf(ib);
    }

    pub fn shift_cl32(&mut self, ext: u8, dst: Reg) {
        let mut ib = InstBuf::new();
        if dst.needs_rex() {
            ib.push(0x40 | dst.hi());
        }
        ib.push(0xD3);
        ib.push(0xC0 | (ext << 3) | dst.lo());
        self.flush_instbuf(ib);
    }

    pub fn shl_ri64(&mut self, dst: Reg, imm: u8) {
        self.shift_ri64(4, dst, imm);
    }
    pub fn shr_ri64(&mut self, dst: Reg, imm: u8) {
        self.shift_ri64(5, dst, imm);
    }
    pub fn sar_ri64(&mut self, dst: Reg, imm: u8) {
        self.shift_ri64(7, dst, imm);
    }
    pub fn shl_cl64(&mut self, dst: Reg) {
        self.shift_cl64(4, dst);
    }
    pub fn shr_cl64(&mut self, dst: Reg) {
        self.shift_cl64(5, dst);
    }
    pub fn sar_cl64(&mut self, dst: Reg) {
        self.shift_cl64(7, dst);
    }
    pub fn rol_cl64(&mut self, dst: Reg) {
        self.shift_cl64(0, dst);
    }
    pub fn ror_cl64(&mut self, dst: Reg) {
        self.shift_cl64(1, dst);
    }
    pub fn rol_ri64(&mut self, dst: Reg, imm: u8) {
        self.shift_ri64(0, dst, imm);
    }
    pub fn ror_ri64(&mut self, dst: Reg, imm: u8) {
        self.shift_ri64(1, dst, imm);
    }

    pub fn shl_ri32(&mut self, dst: Reg, imm: u8) {
        self.shift_ri32(4, dst, imm);
    }
    pub fn shr_ri32(&mut self, dst: Reg, imm: u8) {
        self.shift_ri32(5, dst, imm);
    }
    pub fn sar_ri32(&mut self, dst: Reg, imm: u8) {
        self.shift_ri32(7, dst, imm);
    }
    pub fn shl_cl32(&mut self, dst: Reg) {
        self.shift_cl32(4, dst);
    }
    pub fn shr_cl32(&mut self, dst: Reg) {
        self.shift_cl32(5, dst);
    }
    pub fn sar_cl32(&mut self, dst: Reg) {
        self.shift_cl32(7, dst);
    }
    pub fn rol_cl32(&mut self, dst: Reg) {
        self.shift_cl32(0, dst);
    }
    pub fn ror_cl32(&mut self, dst: Reg) {
        self.shift_cl32(1, dst);
    }
    pub fn rol_ri32(&mut self, dst: Reg, imm: u8) {
        self.shift_ri32(0, dst, imm);
    }
    pub fn ror_ri32(&mut self, dst: Reg, imm: u8) {
        self.shift_ri32(1, dst, imm);
    }

    // -- Extensions --

    /// movsxd r64, r32 (sign-extend 32→64)
    #[inline(always)]
    pub fn movsxd(&mut self, dst: Reg, src: Reg) {
        let mut ib = InstBuf::new();
        ib.push(0x48 | (dst.hi() << 2) | src.hi());
        ib.push(0x63);
        ib.push(0xC0 | (dst.lo() << 3) | src.lo());
        self.flush_instbuf(ib);
    }

    /// movsx r64, r8 (sign-extend 8→64)
    pub fn movsx_8_64(&mut self, dst: Reg, src: Reg) {
        let mut ib = InstBuf::new();
        ib.push(0x48 | (dst.hi() << 2) | src.hi());
        ib.push(0x0F);
        ib.push(0xBE);
        ib.push(0xC0 | (dst.lo() << 3) | src.lo());
        self.flush_instbuf(ib);
    }

    /// movsx r64, r16 (sign-extend 16→64)
    pub fn movsx_16_64(&mut self, dst: Reg, src: Reg) {
        let mut ib = InstBuf::new();
        ib.push(0x48 | (dst.hi() << 2) | src.hi());
        ib.push(0x0F);
        ib.push(0xBF);
        ib.push(0xC0 | (dst.lo() << 3) | src.lo());
        self.flush_instbuf(ib);
    }

    /// movzx r64, r8 (zero-extend 8→64)
    pub fn movzx_8_64(&mut self, dst: Reg, src: Reg) {
        let mut ib = InstBuf::new();
        ib.push(0x48 | (dst.hi() << 2) | src.hi());
        ib.push(0x0F);
        ib.push(0xB6);
        ib.push(0xC0 | (dst.lo() << 3) | src.lo());
        self.flush_instbuf(ib);
    }

    /// movzx r32, r16 (zero-extends to 64 due to 32-bit operation)
    pub fn movzx_16_64(&mut self, dst: Reg, src: Reg) {
        let mut ib = InstBuf::new();
        let r = dst.hi();
        let b = src.hi();
        if r != 0 || b != 0 {
            ib.push(0x40 | (r << 2) | b);
        }
        ib.push(0x0F);
        ib.push(0xB7);
        ib.push(0xC0 | (dst.lo() << 3) | src.lo());
        self.flush_instbuf(ib);
    }

    /// Zero-extend 32→64: mov r32, r32 (implicit zero-extend)
    #[inline(always)]
    pub fn movzx_32_64(&mut self, dst: Reg, src: Reg) {
        let mut ib = InstBuf::new();
        let r = src.hi();
        let b = dst.hi();
        if r != 0 || b != 0 {
            ib.push(0x40 | (r << 2) | b);
        }
        ib.push(0x89);
        ib.push(0xC0 | (src.lo() << 3) | dst.lo());
        self.flush_instbuf(ib);
    }

    // -- Conditional set --

    /// setcc r8 (sets low byte, need to movzx after)
    #[inline(always)]
    pub fn setcc(&mut self, cc: Cc, dst: Reg) {
        let mut ib = InstBuf::new();
        if dst.needs_rex() || matches!(dst, Reg::RSP | Reg::RBP | Reg::RSI | Reg::RDI) {
            ib.push(0x40 | dst.hi());
        }
        ib.push(0x0F);
        ib.push(0x90 + cc as u8);
        ib.push(0xC0 | dst.lo());
        self.flush_instbuf(ib);
    }

    /// cmovcc r64, r64
    #[inline(always)]
    pub fn cmovcc(&mut self, cc: Cc, dst: Reg, src: Reg) {
        let mut ib = InstBuf::new();
        ib.push(0x48 | (dst.hi() << 2) | src.hi());
        ib.push(0x0F);
        ib.push(0x40 + cc as u8);
        ib.push(0xC0 | (dst.lo() << 3) | src.lo());
        self.flush_instbuf(ib);
    }

    // -- Bit manipulation (require BMI/POPCNT support) --

    /// popcnt r64, r64
    pub fn popcnt64(&mut self, dst: Reg, src: Reg) {
        let mut ib = InstBuf::new();
        ib.push(0xF3);
        ib.push(0x48 | (dst.hi() << 2) | src.hi());
        ib.push(0x0F);
        ib.push(0xB8);
        ib.push(0xC0 | (dst.lo() << 3) | src.lo());
        self.flush_instbuf(ib);
    }

    /// lzcnt r64, r64
    pub fn lzcnt64(&mut self, dst: Reg, src: Reg) {
        let mut ib = InstBuf::new();
        ib.push(0xF3);
        ib.push(0x48 | (dst.hi() << 2) | src.hi());
        ib.push(0x0F);
        ib.push(0xBD);
        ib.push(0xC0 | (dst.lo() << 3) | src.lo());
        self.flush_instbuf(ib);
    }

    /// tzcnt r64, r64
    pub fn tzcnt64(&mut self, dst: Reg, src: Reg) {
        let mut ib = InstBuf::new();
        ib.push(0xF3);
        ib.push(0x48 | (dst.hi() << 2) | src.hi());
        ib.push(0x0F);
        ib.push(0xBC);
        ib.push(0xC0 | (dst.lo() << 3) | src.lo());
        self.flush_instbuf(ib);
    }

    /// bswap r64
    pub fn bswap64(&mut self, dst: Reg) {
        self.emit3(0x48 | dst.hi(), 0x0F, 0xC8 + dst.lo());
    }

    // -- Stack --

    #[inline(always)]
    pub fn push(&mut self, reg: Reg) {
        self.rex_opt_b(reg);
        self.emit(0x50 + reg.lo());
    }

    #[inline(always)]
    pub fn pop(&mut self, reg: Reg) {
        self.rex_opt_b(reg);
        self.emit(0x58 + reg.lo());
    }

    /// push sign-extended imm32 (5 bytes: 0x68 + imm32).
    pub fn push_imm32(&mut self, imm: i32) {
        self.emit(0x68);
        self.emit_i32(imm);
    }

    // -- Branches and jumps --

    /// jmp to label — uses rel8 for backward jumps within ±127 bytes.
    #[inline(always)]
    pub fn jmp_label(&mut self, label: Label) {
        let bound = self.labels[label.0 as usize];
        if bound != LABEL_UNBOUND {
            let target = (bound - 1) as isize; // stored as offset+1
            // Backward jump — label already bound, try rel8.
            let rel = target - (self.write_pos as isize + 2);
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
    #[inline(always)]
    pub fn jcc_label(&mut self, cc: Cc, label: Label) {
        let bound = self.labels[label.0 as usize];
        if bound != LABEL_UNBOUND {
            let target = (bound - 1) as isize; // stored as offset+1
            // Backward jump — label already bound, try rel8.
            let rel = target - (self.write_pos as isize + 2);
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
        let mut ib = InstBuf::new();
        ib.push(0x48 | (dst.hi() << 2) | base.hi());
        ib.push(0x8D);
        Self::modrm_disp_ib(&mut ib, dst.lo(), base, disp);
        self.flush_instbuf(ib);
    }

    /// lea r32, [base + disp] — 32-bit result, zero-extends to 64-bit.
    #[inline(always)]
    pub fn lea_32(&mut self, dst: Reg, base: Reg, disp: i32) {
        let mut ib = InstBuf::new();
        let r = dst.hi();
        let b = base.hi();
        if r != 0 || b != 0 {
            ib.push(0x40 | (r << 2) | b);
        }
        ib.push(0x8D);
        Self::modrm_disp_ib(&mut ib, dst.lo(), base, disp);
        self.flush_instbuf(ib);
    }

    /// lea r32, [base32 + index32 * (1 << scale_log2)]
    /// scale_log2: 0=*1, 1=*2, 2=*4, 3=*8
    #[inline(always)]
    pub fn lea_sib_scaled_32(&mut self, dst: Reg, base: Reg, index: Reg, scale_log2: u8) {
        debug_assert!(scale_log2 <= 3);
        let mut ib = InstBuf::new();
        let rex = 0x40 | (dst.hi() << 2) | (index.hi() << 1) | base.hi();
        if rex != 0x40 {
            ib.push(rex);
        }
        ib.push(0x8D);
        let scale_bits = scale_log2 << 6;
        if base.lo() == 5 {
            ib.push(0x44 | (dst.lo() << 3));
            ib.push(scale_bits | (index.lo() << 3) | base.lo());
            ib.push(0x00);
        } else {
            ib.push((dst.lo() << 3) | 0x04);
            ib.push(scale_bits | (index.lo() << 3) | base.lo());
        }
        self.flush_instbuf(ib);
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
        if off == LABEL_UNBOUND {
            None
        } else {
            Some((off - 1) as usize)
        }
    }

    /// Sync Vec length with the write cursor. Call before accessing `self.code` directly.
    pub fn sync_len(&mut self) {
        if let CodeBuf::Vec(code) = &mut self.code_buf {
            unsafe {
                code.set_len(self.write_pos);
            }
        }
    }

    /// Resolve all label fixups in-place (works for both Vec and mmap buffers).
    fn resolve_fixups(&mut self) {
        for fixup in &self.fixups {
            let stored = self.labels[fixup.label.0 as usize];
            // All labels must be bound by finalization time.
            assert!(stored != LABEL_UNBOUND, "unbound label {:?}", fixup.label);
            let target = stored - 1; // stored as offset+1
            let rel = (target as i64) - (fixup.offset as i64 + 4);
            let rel32 = rel as i32;
            unsafe {
                std::ptr::copy_nonoverlapping(
                    rel32.to_le_bytes().as_ptr(),
                    self.buf.add(fixup.offset),
                    4,
                );
            }
        }
    }

    /// Resolve fixups and return the code as a Vec<u8> (for Vec-backed buffers).
    pub fn finalize(&mut self) -> Vec<u8> {
        self.resolve_fixups();
        match &mut self.code_buf {
            CodeBuf::Vec(code) => {
                unsafe {
                    code.set_len(self.write_pos);
                }
                std::mem::take(code)
            }
            CodeBuf::Mmap { ptr, capacity } => {
                // Copy from mmap to Vec (fallback path)
                let mut v = Vec::with_capacity(self.write_pos);
                unsafe {
                    std::ptr::copy_nonoverlapping(*ptr, v.as_mut_ptr(), self.write_pos);
                    v.set_len(self.write_pos);
                    libc::munmap(*ptr as *mut libc::c_void, *capacity);
                }
                *ptr = std::ptr::null_mut();
                *capacity = 0;
                v
            }
        }
    }

    /// Resolve fixups, mprotect the buffer to PROT_READ|PROT_EXEC, and return
    /// the executable buffer pointer and length. Only works for mmap-backed buffers.
    /// Returns (ptr, code_len, mmap_capacity) for NativeCode construction.
    pub fn finalize_executable(&mut self) -> Result<(*mut u8, usize, usize), String> {
        self.resolve_fixups();
        match &mut self.code_buf {
            CodeBuf::Mmap { ptr, capacity } => {
                let code_len = self.write_pos;
                let p = *ptr;
                let cap = *capacity;
                unsafe {
                    if libc::mprotect(
                        p as *mut libc::c_void,
                        cap,
                        libc::PROT_READ | libc::PROT_EXEC,
                    ) != 0
                    {
                        libc::munmap(p as *mut libc::c_void, cap);
                        *ptr = std::ptr::null_mut();
                        *capacity = 0;
                        return Err("mprotect failed".into());
                    }
                }
                // Prevent Drop from double-freeing — ownership transfers to caller
                *ptr = std::ptr::null_mut();
                *capacity = 0;
                Ok((p, code_len, cap))
            }
            CodeBuf::Vec(_) => Err("finalize_executable requires mmap-backed buffer".into()),
        }
    }

    /// Get a slice of the written code bytes (for tests). Syncs Vec len first.
    #[cfg(test)]
    pub fn code_bytes(&mut self) -> &[u8] {
        self.sync_len();
        match &self.code_buf {
            CodeBuf::Vec(v) => v.as_slice(),
            CodeBuf::Mmap { ptr, .. } => unsafe {
                std::slice::from_raw_parts(*ptr, self.write_pos)
            },
        }
    }
}

impl Drop for Assembler {
    fn drop(&mut self) {
        if let CodeBuf::Mmap { ptr, capacity } = self.code_buf
            && !ptr.is_null()
            && capacity > 0
        {
            unsafe {
                libc::munmap(ptr as *mut libc::c_void, capacity);
            }
        }
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
        assert_eq!(asm.code_bytes(), &[0x31, 0xC0]);
    }

    #[test]
    fn test_mov_ri64_small() {
        let mut asm = Assembler::new();
        asm.mov_ri64(Reg::RAX, 42);
        // mov eax, 42 → 0xB8, 0x2A, 0x00, 0x00, 0x00
        assert_eq!(asm.code_bytes(), &[0xB8, 0x2A, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_label_resolution() {
        let mut asm = Assembler::new();
        let lbl = asm.new_label();
        asm.jmp_label(lbl); // 5 bytes: E9 + 4-byte rel32
        asm.nop(); // 1 byte at offset 5
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
        assert_eq!(asm.code_bytes(), &[0x41, 0x57, 0x41, 0x5F]);
    }
}
