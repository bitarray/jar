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

use std::fs::File;
use std::io::Read;
use std::vec::Vec;

use super::elf::ElfInfo;
use super::ptr_offset::Offset;
use crate::Result;

pub enum ExeInfo {
    Elf(ElfInfo),
}

#[derive(Clone)]
pub(crate) struct LoadInfo {}

impl ExeInfo {
    pub fn from_file(path: &str) -> Result<Self> {
        let mut file = File::open(path)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        Self::from_buf(&contents)
    }
    pub fn from_buf(buf: &[u8]) -> Result<Self> {
        ElfInfo::new(buf).map(ExeInfo::Elf)
    }
    pub fn entrypoint(&self) -> Offset {
        match self {
            ExeInfo::Elf(elf) => Offset::from(elf.entrypoint_va()),
        }
    }
    /// Returns the base virtual address of the loaded binary (lowest PT_LOAD p_vaddr).
    pub fn base_va(&self) -> u64 {
        match self {
            ExeInfo::Elf(elf) => elf.get_base_va(),
        }
    }
    pub fn loaded_size(&self) -> usize {
        match self {
            ExeInfo::Elf(elf) => elf.get_va_size(),
        }
    }

    /// Returns the hyperlight version string embedded in the guest binary, if
    /// the binary was built with a version of `hyperlight-guest-bin` that
    /// supports version tagging.
    pub fn guest_bin_version(&self) -> Option<&str> {
        match self {
            ExeInfo::Elf(elf) => elf.guest_bin_version(),
        }
    }
    // Takes `self` by value: the ELF loader copies PT_LOAD segments
    // into `target` and applies relocations against `runtime_base_va`.
    /// Load the executable into `target`. `runtime_base_va` is the
    /// GVA at which the guest will see the loaded image — applied as
    /// the base for `R_X86_64_RELATIVE` / `R_AARCH64_RELATIVE`
    /// relocations so runtime pointers resolve to kernel-half VAs.
    pub fn load(self, runtime_base_va: u64, target: &mut [u8]) -> Result<LoadInfo> {
        match self {
            ExeInfo::Elf(elf) => elf.load_at(runtime_base_va, target),
        }
    }
}
