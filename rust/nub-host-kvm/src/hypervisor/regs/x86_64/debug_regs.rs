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
use kvm_bindings::kvm_debugregs;

/// Common abstraction for x86 debug registers (DR0-DR7).
#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub(crate) struct CommonDebugRegs {
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
}

#[cfg(kvm)]
impl From<kvm_debugregs> for CommonDebugRegs {
    fn from(kvm_regs: kvm_debugregs) -> Self {
        Self {
            dr0: kvm_regs.db[0],
            dr1: kvm_regs.db[1],
            dr2: kvm_regs.db[2],
            dr3: kvm_regs.db[3],
            dr6: kvm_regs.dr6,
            dr7: kvm_regs.dr7,
        }
    }
}
#[cfg(kvm)]
impl From<&CommonDebugRegs> for kvm_debugregs {
    fn from(common_regs: &CommonDebugRegs) -> Self {
        kvm_debugregs {
            db: [
                common_regs.dr0,
                common_regs.dr1,
                common_regs.dr2,
                common_regs.dr3,
            ],
            dr6: common_regs.dr6,
            dr7: common_regs.dr7,
            ..Default::default()
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn common_debug_regs() -> CommonDebugRegs {
        CommonDebugRegs {
            dr0: 1,
            dr1: 2,
            dr2: 3,
            dr3: 4,
            dr6: 5,
            dr7: 6,
        }
    }

    #[cfg(kvm)]
    #[test]
    fn round_trip_kvm_debug_regs() {
        let original = common_debug_regs();
        let kvm_regs: kvm_debugregs = (&original).into();
        let converted: CommonDebugRegs = kvm_regs.into();
        assert_eq!(original, converted);
    }
}
