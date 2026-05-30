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

use std::fmt::Debug;
use std::option::Option;
use std::path::Path;
use std::sync::{Arc, Mutex};

use tracing::{Span, instrument};
use tracing_core::LevelFilter;

use super::host_funcs::FunctionRegistry;
use super::snapshot::Snapshot;
use super::uninitialized_evolve::evolve_impl_multi_use;
use crate::func::HostFn;
use crate::func::host_functions::register_host_function;
use crate::mem::memory_region::{DEFAULT_GUEST_BLOB_MEM_FLAGS, MemoryRegionFlags};
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::shared_mem::{ExclusiveSharedMemory, SharedMemory};
use crate::sandbox::SandboxConfiguration;
use crate::{MultiUseSandbox, Result, new_error};

/// A preliminary sandbox that represents allocated memory and registered host functions,
/// but has not yet created the underlying virtual machine.
///
/// This struct holds the configuration and setup needed for a sandbox without actually
/// creating the VM. It allows you to:
/// - Set up memory layout and load guest binary data
/// - Register host functions that will be available to the guest
/// - Configure sandbox settings before VM creation
///
/// The virtual machine is not created until you call [`evolve`](Self::evolve) to transform
/// this into an initialized [`MultiUseSandbox`].
pub struct UninitializedSandbox {
    /// Registered host functions
    pub(crate) host_funcs: Arc<Mutex<FunctionRegistry>>,
    /// The memory manager for the sandbox.
    pub(crate) mgr: SandboxMemoryManager<ExclusiveSharedMemory>,
    pub(crate) max_guest_log_level: Option<LevelFilter>,
    pub(crate) config: SandboxConfiguration,
    pub(crate) load_info: crate::mem::exe::LoadInfo,
    // This is needed to convey the stack pointer between the snapshot
    // and the HyperlightVm creation
    pub(crate) stack_top_gva: u64,
}

impl Debug for UninitializedSandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UninitializedSandbox")
            .field("memory_layout", &self.mgr.layout)
            .finish()
    }
}

/// A `GuestBinary` is either a buffer or the file path to some data (e.g., a guest binary).
#[derive(Debug)]
pub enum GuestBinary<'a> {
    /// A buffer containing the GuestBinary
    Buffer(&'a [u8]),
    /// A path to the GuestBinary
    FilePath(String),
}
impl<'a> GuestBinary<'a> {
    /// If the guest binary is identified by a file, canonicalise the path
    ///
    /// For [`GuestBinary::FilePath`], this resolves the path to its canonical
    /// form. For [`GuestBinary::Buffer`], this method is a no-op.
    /// TODO: Maybe we should make the GuestEnvironment or
    ///       GuestBinary constructors crate-private and turn this
    ///       into an invariant on one of those types.
    pub fn canonicalize(&mut self) -> Result<()> {
        if let GuestBinary::FilePath(p) = self {
            let canon = Path::new(&p)
                .canonicalize()
                .map_err(|e| new_error!("GuestBinary not found: '{}': {}", p, e))?
                .into_os_string()
                .into_string()
                .map_err(|e| new_error!("Error converting OsString to String: {:?}", e))?;
            *self = GuestBinary::FilePath(canon)
        }
        Ok(())
    }
}

/// A `GuestBlob` containing data and the permissions for its use.
#[derive(Debug)]
pub struct GuestBlob<'a> {
    /// The data contained in the blob.
    pub data: &'a [u8],
    /// The permissions for the blob in memory.
    /// By default, it's READ
    pub permissions: MemoryRegionFlags,
}

impl<'a> From<&'a [u8]> for GuestBlob<'a> {
    fn from(data: &'a [u8]) -> Self {
        GuestBlob {
            data,
            permissions: DEFAULT_GUEST_BLOB_MEM_FLAGS,
        }
    }
}

/// Container for a guest binary and optional initialization data.
///
/// This struct combines a guest binary (either from a file or memory buffer) with
/// optional data that will be available to the guest during execution.
#[derive(Debug)]
pub struct GuestEnvironment<'a, 'b> {
    /// The guest binary, which can be a file path or a buffer.
    pub guest_binary: GuestBinary<'a>,
    /// An optional guest blob, which can be used to provide additional data to the guest.
    pub init_data: Option<GuestBlob<'b>>,
}

impl<'a, 'b> GuestEnvironment<'a, 'b> {
    /// Creates a new `GuestEnvironment` with the given guest binary and an optional guest blob.
    pub fn new(guest_binary: GuestBinary<'a>, init_data: Option<&'b [u8]>) -> Self {
        GuestEnvironment {
            guest_binary,
            init_data: init_data.map(GuestBlob::from),
        }
    }
}

impl<'a> From<GuestBinary<'a>> for GuestEnvironment<'a, '_> {
    fn from(guest_binary: GuestBinary<'a>) -> Self {
        GuestEnvironment {
            guest_binary,
            init_data: None,
        }
    }
}

impl UninitializedSandbox {
    // Creates a new uninitialized sandbox from a pre-built snapshot.
    // Note that since memory configuration is part of the snapshot the only configuration
    // that can be changed (from the original snapshot) is that defines the behaviour of
    // `InterruptHandle` on Linux.
    //
    // This is ok for now as this is not a public function
    fn from_snapshot(snapshot: Arc<Snapshot>, cfg: Option<SandboxConfiguration>) -> Result<Self> {
        let sandbox_cfg = cfg.unwrap_or_default();

        let mem_mgr_wrapper =
            SandboxMemoryManager::<ExclusiveSharedMemory>::from_snapshot(snapshot.as_ref())?;

        let host_funcs = Arc::new(Mutex::new(FunctionRegistry::default()));

        let sandbox = Self {
            host_funcs,
            mgr: mem_mgr_wrapper,
            max_guest_log_level: None,
            config: sandbox_cfg,
            load_info: snapshot.load_info(),
            stack_top_gva: snapshot.stack_top_gva(),
        };

        // Upstream registered a default "HostPrint" handler here.
        // After the FB/SCALE → rkyv migration, host functions are
        // fn_id-indexed and there is no host-print integration; if a
        // future caller needs guest stdout it can register a handler
        // explicitly via `register_host_function`.

        crate::debug!("Sandbox created:  {:#?}", sandbox);

        Ok(sandbox)
    }

    /// Creates a new uninitialized sandbox for the given guest environment.
    ///
    /// The guest binary can be provided as either a file path or memory buffer.
    /// An optional configuration can customize memory sizes and sandbox settings.
    /// After creation, register host functions using [`register`](Self::register)
    /// before calling [`evolve`](Self::evolve) to complete initialization and create the VM.
    #[instrument(
        err(Debug),
        skip(env),
        parent = Span::current()
    )]
    pub fn new<'a, 'b>(
        env: impl Into<GuestEnvironment<'a, 'b>>,
        cfg: Option<SandboxConfiguration>,
    ) -> Result<Self> {
        let cfg = cfg.unwrap_or_default();
        let env = env.into();
        let snapshot = Snapshot::from_env(env, cfg)?;
        Self::from_snapshot(Arc::new(snapshot), Some(cfg))
    }

    /// Creates and initializes the virtual machine, transforming this into a ready-to-use sandbox.
    ///
    /// This method consumes the `UninitializedSandbox` and performs the final initialization
    /// steps to create the underlying virtual machine. Once evolved, the resulting
    /// [`MultiUseSandbox`] can execute guest code and handle function calls.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub fn evolve(self) -> Result<MultiUseSandbox> {
        evolve_impl_multi_use(self)
    }

    /// Returns the total size of the sandbox shared memory region in bytes.
    ///
    /// This is useful for placing file mappings at guest physical addresses
    /// that don't overlap the primary shared memory slot.
    pub fn shared_mem_size(&self) -> usize {
        self.mgr.shared_mem.mem_size()
    }

    /// Sets the maximum log level for guest code execution.
    ///
    /// If not set, the log level is determined by the `RUST_LOG` environment variable,
    /// defaulting to `LevelFilter::Error` if unset.
    pub fn set_max_guest_log_level(&mut self, log_level: LevelFilter) {
        self.max_guest_log_level = Some(log_level);
    }

    /// Registers a host function under `fn_id` that the guest can
    /// call via the `OutBAction::CallFunction` outb port. The
    /// closure receives the raw `Request.payload` bytes from the
    /// guest and returns the raw response payload bytes.
    pub fn register(&mut self, fn_id: u32, host_func: HostFn) -> Result<()> {
        register_host_function(self, fn_id, host_func)
    }
}
