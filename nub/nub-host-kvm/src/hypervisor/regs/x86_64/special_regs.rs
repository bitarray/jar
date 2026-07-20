/*
Copyright 2025  The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#[cfg(kvm)]
use kvm_bindings::{kvm_dtable, kvm_segment, kvm_sregs};

// CR0 bits used by both 32-bit and 64-bit guest
const CR0_PE: u64 = 1;
const CR0_ET: u64 = 1 << 4;
const CR0_WP: u64 = 1 << 16;
const CR0_PG: u64 = 1 << 31;

mod amd64_consts {
    pub(crate) const CR4_PAE: u64 = 1 << 5;
    pub(crate) const CR4_OSFXSR: u64 = 1 << 9;
    pub(crate) const CR4_OSXMMEXCPT: u64 = 1 << 10;
    pub(crate) const CR0_MP: u64 = 1 << 1;
    pub(crate) const CR0_NE: u64 = 1 << 5;
    pub(crate) const CR0_AM: u64 = 1 << 18;
    pub(crate) const EFER_LME: u64 = 1 << 8;
    pub(crate) const EFER_LMA: u64 = 1 << 10;
    pub(crate) const EFER_SCE: u64 = 1;
    pub(crate) const EFER_NX: u64 = 1 << 11;
}
use amd64_consts::*;

#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub(crate) struct CommonSpecialRegisters {
    pub cs: CommonSegmentRegister,
    pub ds: CommonSegmentRegister,
    pub es: CommonSegmentRegister,
    pub fs: CommonSegmentRegister,
    pub gs: CommonSegmentRegister,
    pub ss: CommonSegmentRegister,
    pub tr: CommonSegmentRegister,
    pub ldt: CommonSegmentRegister,
    pub gdt: CommonTableRegister,
    pub idt: CommonTableRegister,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub interrupt_bitmap: [u64; 4],
}

impl CommonSpecialRegisters {
    pub(crate) fn standard_64bit_defaults(root_pt_addr: u64) -> Self {
        CommonSpecialRegisters {
            cs: CommonSegmentRegister {
                l: 1,          // 64-bit
                type_: 0b1011, // Code, Readable, Accessed
                present: 1,    // Present
                s: 1,          // Non-system
                ..Default::default()
            },
            tr: CommonSegmentRegister {
                limit: 0xFFFF,
                type_: 0b1011,
                present: 1,
                ..Default::default()
            },
            efer: EFER_LME | EFER_LMA | EFER_SCE | EFER_NX,
            ds: Default::default(),
            es: Default::default(),
            fs: Default::default(),
            gs: Default::default(),
            ss: Default::default(),
            ldt: Default::default(),
            gdt: Default::default(),
            idt: Default::default(),
            cr0: CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_AM | CR0_WP | CR0_PG,
            cr2: 0,
            cr4: CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT,
            cr3: root_pt_addr,
            cr8: 0,
            apic_base: 0,
            interrupt_bitmap: [0; 4],
        }
    }
}

#[cfg(kvm)]
impl From<&kvm_sregs> for CommonSpecialRegisters {
    fn from(kvm_sregs: &kvm_sregs) -> Self {
        CommonSpecialRegisters {
            cs: kvm_sregs.cs.into(),
            ds: kvm_sregs.ds.into(),
            es: kvm_sregs.es.into(),
            fs: kvm_sregs.fs.into(),
            gs: kvm_sregs.gs.into(),
            ss: kvm_sregs.ss.into(),
            tr: kvm_sregs.tr.into(),
            ldt: kvm_sregs.ldt.into(),
            gdt: kvm_sregs.gdt.into(),
            idt: kvm_sregs.idt.into(),
            cr0: kvm_sregs.cr0,
            cr2: kvm_sregs.cr2,
            cr3: kvm_sregs.cr3,
            cr4: kvm_sregs.cr4,
            cr8: kvm_sregs.cr8,
            efer: kvm_sregs.efer,
            apic_base: kvm_sregs.apic_base,
            interrupt_bitmap: kvm_sregs.interrupt_bitmap,
        }
    }
}

#[cfg(kvm)]
impl From<&CommonSpecialRegisters> for kvm_sregs {
    fn from(common_sregs: &CommonSpecialRegisters) -> Self {
        kvm_sregs {
            cs: common_sregs.cs.into(),
            ds: common_sregs.ds.into(),
            es: common_sregs.es.into(),
            fs: common_sregs.fs.into(),
            gs: common_sregs.gs.into(),
            ss: common_sregs.ss.into(),
            tr: common_sregs.tr.into(),
            ldt: common_sregs.ldt.into(),
            gdt: common_sregs.gdt.into(),
            idt: common_sregs.idt.into(),
            cr0: common_sregs.cr0,
            cr2: common_sregs.cr2,
            cr3: common_sregs.cr3,
            cr4: common_sregs.cr4,
            cr8: common_sregs.cr8,
            efer: common_sregs.efer,
            apic_base: common_sregs.apic_base,
            interrupt_bitmap: common_sregs.interrupt_bitmap,
        }
    }
}

// --- Segment Register ---

#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub(crate) struct CommonSegmentRegister {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub type_: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    pub avl: u8,
    pub unusable: u8,
    pub padding: u8,
}

#[cfg(kvm)]
impl From<kvm_segment> for CommonSegmentRegister {
    fn from(kvm_segment: kvm_segment) -> Self {
        CommonSegmentRegister {
            base: kvm_segment.base,
            limit: kvm_segment.limit,
            selector: kvm_segment.selector,
            type_: kvm_segment.type_,
            present: kvm_segment.present,
            dpl: kvm_segment.dpl,
            db: kvm_segment.db,
            s: kvm_segment.s,
            l: kvm_segment.l,
            g: kvm_segment.g,
            avl: kvm_segment.avl,
            unusable: kvm_segment.unusable,
            padding: kvm_segment.padding,
        }
    }
}

#[cfg(kvm)]
impl From<CommonSegmentRegister> for kvm_segment {
    fn from(common_segment: CommonSegmentRegister) -> Self {
        kvm_segment {
            base: common_segment.base,
            limit: common_segment.limit,
            selector: common_segment.selector,
            type_: common_segment.type_,
            present: common_segment.present,
            dpl: common_segment.dpl,
            db: common_segment.db,
            s: common_segment.s,
            l: common_segment.l,
            g: common_segment.g,
            avl: common_segment.avl,
            unusable: common_segment.unusable,
            padding: common_segment.padding,
        }
    }
}

// --- Table Register ---

#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub(crate) struct CommonTableRegister {
    pub base: u64,
    pub limit: u16,
}

#[cfg(kvm)]
impl From<kvm_dtable> for CommonTableRegister {
    fn from(kvm_dtable: kvm_dtable) -> Self {
        CommonTableRegister {
            base: kvm_dtable.base,
            limit: kvm_dtable.limit,
        }
    }
}

#[cfg(kvm)]
impl From<CommonTableRegister> for kvm_dtable {
    fn from(common_dtable: CommonTableRegister) -> Self {
        kvm_dtable {
            base: common_dtable.base,
            limit: common_dtable.limit,
            padding: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_common_special_registers() -> CommonSpecialRegisters {
        let sample_segment = CommonSegmentRegister {
            base: 0x1000,
            limit: 0xFFFF,
            selector: 0x10,
            type_: 0xB,
            present: 1,
            dpl: 0,
            db: 1,
            s: 1,
            l: 0,
            g: 1,
            avl: 0,
            unusable: 0,
            padding: 0,
        };

        let sample_table = CommonTableRegister {
            base: 0x2000,
            limit: 0x1000,
        };

        CommonSpecialRegisters {
            cs: sample_segment,
            ds: sample_segment,
            es: sample_segment,
            fs: sample_segment,
            gs: sample_segment,
            ss: sample_segment,
            tr: sample_segment,
            ldt: sample_segment,
            gdt: sample_table,
            idt: sample_table,
            cr0: 0xDEAD_BEEF,
            cr2: 0xBAD_C0DE,
            cr3: 0xC0FFEE,
            cr4: 0xFACE_CAFE,
            cr8: 0x1234,
            efer: 0x5678,
            apic_base: 0x9ABC,
            interrupt_bitmap: [0; 4],
        }
    }

    #[cfg(kvm)]
    #[test]
    fn round_trip_kvm_sregs() {
        let original = sample_common_special_registers();
        let kvm_sregs: kvm_sregs = (&original).into();
        let roundtrip = CommonSpecialRegisters::from(&kvm_sregs);

        assert_eq!(original, roundtrip);
    }
}
