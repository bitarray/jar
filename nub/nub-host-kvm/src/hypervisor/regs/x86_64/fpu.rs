/*
Copyright 2024 The Hyperlight Authors.

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
use kvm_bindings::kvm_fpu;

pub(crate) const FP_CONTROL_WORD_DEFAULT: u16 = 0x37f; // mask all fp-exception, set rounding to nearest, set precision to 64-bit
pub(crate) const MXCSR_DEFAULT: u32 = 0x1f80; // mask simd fp-exceptions, clear exception flags, set rounding to nearest, disable flush-to-zero mode, disable denormals-are-zero mode

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct CommonFpu {
    pub fpr: [[u8; 16]; 8],
    pub fcw: u16,
    pub fsw: u16,
    pub ftwx: u8,
    pub last_opcode: u16,
    pub last_ip: u64,
    pub last_dp: u64,
    pub xmm: [[u8; 16]; 16],
    pub mxcsr: u32,
}

impl Default for CommonFpu {
    fn default() -> Self {
        Self {
            fpr: [[0u8; 16]; 8],
            fcw: FP_CONTROL_WORD_DEFAULT,
            fsw: 0,
            ftwx: 0,
            last_opcode: 0,
            last_ip: 0,
            last_dp: 0,
            xmm: [[0u8; 16]; 16],
            mxcsr: MXCSR_DEFAULT,
        }
    }
}

#[cfg(kvm)]
impl From<&CommonFpu> for kvm_fpu {
    fn from(common_fpu: &CommonFpu) -> Self {
        kvm_fpu {
            fpr: common_fpu.fpr,
            fcw: common_fpu.fcw,
            fsw: common_fpu.fsw,
            ftwx: common_fpu.ftwx,
            pad1: 0,
            last_opcode: common_fpu.last_opcode,
            last_ip: common_fpu.last_ip,
            last_dp: common_fpu.last_dp,
            xmm: common_fpu.xmm,
            mxcsr: common_fpu.mxcsr,
            pad2: 0,
        }
    }
}

#[cfg(kvm)]
impl From<&kvm_fpu> for CommonFpu {
    fn from(kvm_fpu: &kvm_fpu) -> Self {
        Self {
            fpr: kvm_fpu.fpr,
            fcw: kvm_fpu.fcw,
            fsw: kvm_fpu.fsw,
            ftwx: kvm_fpu.ftwx,
            last_opcode: kvm_fpu.last_opcode,
            last_ip: kvm_fpu.last_ip,
            last_dp: kvm_fpu.last_dp,
            xmm: kvm_fpu.xmm,
            mxcsr: kvm_fpu.mxcsr,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_common_fpu() -> CommonFpu {
        CommonFpu {
            fpr: [
                [1u8; 16], [2u8; 16], [3u8; 16], [4u8; 16], [5u8; 16], [6u8; 16], [7u8; 16],
                [8u8; 16],
            ],
            fcw: 0x1234,
            fsw: 0x5678,
            ftwx: 0x9a,
            last_opcode: 0xdef0,
            last_ip: 0xdeadbeefcafebabe,
            last_dp: 0xabad1deaf00dbabe,
            xmm: [
                [8u8; 16], [9u8; 16], [10u8; 16], [11u8; 16], [12u8; 16], [13u8; 16], [14u8; 16],
                [15u8; 16], [16u8; 16], [17u8; 16], [18u8; 16], [19u8; 16], [20u8; 16], [21u8; 16],
                [22u8; 16], [23u8; 16],
            ],
            mxcsr: 0x1f80,
        }
    }

    #[cfg(kvm)]
    #[test]
    fn round_trip_kvm_fpu() {
        use kvm_bindings::kvm_fpu;

        let original = sample_common_fpu();
        let kvm: kvm_fpu = (&original).into();
        let round_tripped = CommonFpu::from(&kvm);

        assert_eq!(original, round_tripped);
    }
}
