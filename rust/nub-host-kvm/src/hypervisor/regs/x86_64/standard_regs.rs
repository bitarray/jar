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
use kvm_bindings::kvm_regs;

#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub(crate) struct CommonRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

// --- KVM ---
#[cfg(kvm)]
impl From<&kvm_regs> for CommonRegisters {
    fn from(kvm_regs: &kvm_regs) -> Self {
        CommonRegisters {
            rax: kvm_regs.rax,
            rbx: kvm_regs.rbx,
            rcx: kvm_regs.rcx,
            rdx: kvm_regs.rdx,
            rsi: kvm_regs.rsi,
            rdi: kvm_regs.rdi,
            rsp: kvm_regs.rsp,
            rbp: kvm_regs.rbp,
            r8: kvm_regs.r8,
            r9: kvm_regs.r9,
            r10: kvm_regs.r10,
            r11: kvm_regs.r11,
            r12: kvm_regs.r12,
            r13: kvm_regs.r13,
            r14: kvm_regs.r14,
            r15: kvm_regs.r15,
            rip: kvm_regs.rip,
            rflags: kvm_regs.rflags,
        }
    }
}

#[cfg(kvm)]
impl From<&CommonRegisters> for kvm_regs {
    fn from(regs: &CommonRegisters) -> Self {
        kvm_regs {
            rax: regs.rax,
            rbx: regs.rbx,
            rcx: regs.rcx,
            rdx: regs.rdx,
            rsi: regs.rsi,
            rdi: regs.rdi,
            rsp: regs.rsp,
            rbp: regs.rbp,
            r8: regs.r8,
            r9: regs.r9,
            r10: regs.r10,
            r11: regs.r11,
            r12: regs.r12,
            r13: regs.r13,
            r14: regs.r14,
            r15: regs.r15,
            rip: regs.rip,
            rflags: regs.rflags,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn common_regs() -> CommonRegisters {
        CommonRegisters {
            rax: 1,
            rbx: 2,
            rcx: 3,
            rdx: 4,
            rsi: 5,
            rdi: 6,
            rsp: 7,
            rbp: 8,
            r8: 9,
            r9: 10,
            r10: 11,
            r11: 12,
            r12: 13,
            r13: 14,
            r14: 15,
            r15: 16,
            rip: 17,
            rflags: 18,
        }
    }
    #[cfg(kvm)]
    #[test]
    fn round_trip_kvm_regs() {
        let original = common_regs();
        let kvm_regs: kvm_regs = (&original).into();
        let converted: CommonRegisters = (&kvm_regs).into();
        assert_eq!(original, converted);
    }
}
