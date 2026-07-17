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

#[cfg(target_arch = "x86_64")]
use goblin::elf::reloc::{R_X86_64_NONE, R_X86_64_RELATIVE};
use goblin::elf::{Elf, ProgramHeaders, Reloc};
use goblin::elf64::program_header::PT_LOAD;

use super::exe::LoadInfo;
use crate::{Result, log_then_return, new_error};

pub(crate) struct ElfInfo {
    payload: Vec<u8>,
    phdrs: ProgramHeaders,
    entry: u64,
    relocs: Vec<Reloc>,
    /// The hyperlight version string embedded by `hyperlight-guest-bin`, if
    /// present. Used to detect version/ABI mismatches between guest and host.
    guest_bin_version: Option<String>,
}

impl ElfInfo {
    pub(crate) fn new(bytes: &[u8]) -> Result<Self> {
        let elf = Elf::parse(bytes)?;
        let relocs = elf.dynrels.iter().chain(elf.dynrelas.iter()).collect();
        if !elf
            .program_headers
            .iter()
            .any(|phdr| phdr.p_type == PT_LOAD)
        {
            log_then_return!("ELF must have at least one PT_LOAD header");
        }

        // Look for the hyperlight version note embedded by
        // hyperlight-guest-bin.
        let guest_bin_version = Self::read_version_note(&elf, bytes);

        Ok(ElfInfo {
            payload: bytes.to_vec(),
            phdrs: elf.program_headers,
            entry: elf.entry,
            relocs,
            guest_bin_version,
        })
    }

    /// Read the hyperlight version note from the ELF binary
    fn read_version_note<'a>(elf: &Elf<'a>, bytes: &'a [u8]) -> Option<String> {
        use nub_host_common::version_note::{
            HYPERLIGHT_NOTE_NAME, HYPERLIGHT_NOTE_TYPE, HYPERLIGHT_VERSION_SECTION,
        };

        let notes = elf.iter_note_sections(bytes, Some(HYPERLIGHT_VERSION_SECTION))?;
        for note in notes {
            let Ok(note) = note else { continue };
            if note.name == HYPERLIGHT_NOTE_NAME && note.n_type == HYPERLIGHT_NOTE_TYPE {
                let desc = core::str::from_utf8(note.desc).ok()?;
                return Some(desc.trim_end_matches('\0').to_string());
            }
        }
        None
    }

    pub(crate) fn entrypoint_va(&self) -> u64 {
        self.entry
    }

    /// Returns the hyperlight version string embedded in the guest binary, if
    /// present. Used to detect version/ABI mismatches between guest and host.
    pub(crate) fn guest_bin_version(&self) -> Option<&str> {
        self.guest_bin_version.as_deref()
    }

    pub(crate) fn get_base_va(&self) -> u64 {
        #[allow(clippy::unwrap_used)] // guaranteed not to panic because of the check in new()
        let min_phdr = self
            .phdrs
            .iter()
            .find(|phdr| phdr.p_type == PT_LOAD)
            .unwrap();
        min_phdr.p_vaddr
    }
    pub(crate) fn get_va_size(&self) -> usize {
        #[allow(clippy::unwrap_used)] // guaranteed not to panic because of the check in new()
        let max_phdr = self
            .phdrs
            .iter()
            .rev()
            .find(|phdr| phdr.p_type == PT_LOAD)
            .unwrap();
        (max_phdr.p_vaddr + max_phdr.p_memsz - self.get_base_va()) as usize
    }
    /// Copy the binary's PT_LOAD segments into `target` and apply
    /// dynamic relocations.
    ///
    /// `runtime_base_va` is the GVA the guest will see for the lowest
    /// PT_LOAD — `R_X86_64_RELATIVE` / `R_AARCH64_RELATIVE` entries
    /// are written as `runtime_base_va + addend` so pointers in
    /// `.data.rel.ro`, linkme tables, etc. resolve to kernel-half VAs
    /// at runtime.
    pub(crate) fn load_at(self, runtime_base_va: u64, target: &mut [u8]) -> Result<LoadInfo> {
        let base_va = self.get_base_va();
        for phdr in self.phdrs.iter().filter(|phdr| phdr.p_type == PT_LOAD) {
            let start_va = (phdr.p_vaddr - base_va) as usize;
            let payload_offset = phdr.p_offset as usize;
            let payload_len = phdr.p_filesz as usize;
            target[start_va..start_va + payload_len]
                .copy_from_slice(&self.payload[payload_offset..payload_offset + payload_len]);
            target[start_va + payload_len..start_va + phdr.p_memsz as usize].fill(0);
        }
        let get_addend = |name, r: &Reloc| {
            r.r_addend
                .ok_or_else(|| new_error!("{} missing addend", name))
        };
        for r in self.relocs.iter() {
            #[cfg(target_arch = "x86_64")]
            match r.r_type {
                R_X86_64_RELATIVE => {
                    let addend = get_addend("R_X86_64_RELATIVE", r)?;
                    target[r.r_offset as usize..r.r_offset as usize + 8]
                        .copy_from_slice(&(runtime_base_va as i64 + addend).to_le_bytes());
                }
                R_X86_64_NONE => {}
                _ => {
                    log_then_return!("unsupported x86_64 relocation {}", r.r_type);
                }
            }
        }
        Ok(LoadInfo {})
    }
}
