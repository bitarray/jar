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
use rand::RngExt;
use tracing::{Span, instrument};

use super::SandboxConfiguration;
use crate::hypervisor::hyperlight_vm::{HyperlightVm, HyperlightVmError};
use crate::mem::exe::LoadInfo;
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::ptr::RawPtr;
use crate::mem::shared_mem::GuestSharedMemory;
#[cfg(target_os = "linux")]
use crate::signal_handlers::setup_signal_handlers;
use crate::{MultiUseSandbox, Result, UninitializedSandbox};

#[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
pub(super) fn evolve_impl_multi_use(u_sbox: UninitializedSandbox) -> Result<MultiUseSandbox> {
    let (mut hshm, gshm) = u_sbox.mgr.build()?;

    // Get the host page size. Narrowed to u32 because the guest ABI
    // passes it via a 32-bit register (rdx), but widened back to usize
    // for host-side alignment calculations in set_up_hypervisor_partition.
    let page_size = u32::try_from(page_size::get())?;

    let mut vm = set_up_hypervisor_partition(
        gshm,
        &u_sbox.config,
        u_sbox.stack_top_gva,
        page_size as usize,
        u_sbox.load_info,
    )?;

    let seed = {
        let mut rng = rand::rng();
        rng.random::<u64>()
    };
    // High GVA — the guest receives this in RDI and dereferences it
    // directly as `*mut HyperlightPEB` (see
    // `nub/nub-arch-guestbin/src/lib.rs::generic_init`). Kernel half
    // lives at `kernel_base_va()`; PEB GPA → GVA via constant offset.
    let peb_addr = {
        let peb_gva = crate::mem::layout::SandboxMemoryLayout::kernel_base_va()
            + (hshm.layout.peb_address as u64
                - crate::mem::layout::SandboxMemoryLayout::BASE_ADDRESS as u64);
        RawPtr::from(peb_gva)
    };

    #[cfg(target_os = "linux")]
    setup_signal_handlers(&u_sbox.config)?;

    vm.initialise(
        peb_addr,
        seed,
        page_size,
        &mut hshm,
        &u_sbox.host_funcs,
        u_sbox.max_guest_log_level,
    )
    .map_err(HyperlightVmError::Initialize)?;

    Ok(MultiUseSandbox::from_uninit(u_sbox.host_funcs, hshm, vm))
}

pub(crate) fn set_up_hypervisor_partition(
    mgr: SandboxMemoryManager<GuestSharedMemory>,
    config: &SandboxConfiguration,
    stack_top_gva: u64,
    page_size: usize,
    _load_info: LoadInfo,
) -> Result<HyperlightVm> {
    // Reserve the GUEST_VA range once per process. Later mmaps of
    // guest-visible regions (snapshot kernel-shadow, etc.) land at
    // fixed VAs inside this reservation. Errors here are fatal: we
    // can't continue if something is squatting on our VA range.
    nub_host_common::layout::reserve_guest_va_range()
        .map_err(|e| crate::new_error!("reserve_guest_va_range: {e}"))?;

    Ok(HyperlightVm::new(
        mgr.shared_mem,
        mgr.scratch_mem,
        mgr.layout.get_pt_base_gpa(),
        mgr.entrypoint,
        stack_top_gva,
        page_size,
        config,
    )
    .map_err(HyperlightVmError::Create)?)
}
