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

use super::host_funcs::{FunctionRegistry, default_writer_func};
use super::snapshot::Snapshot;
use super::uninitialized_evolve::evolve_impl_multi_use;
use crate::func::host_functions::{HostFunction, register_host_function};
use crate::func::{ParameterTuple, SupportedReturnType};
#[cfg(feature = "build-metadata")]
use crate::log_build_details;
use crate::mem::memory_region::{DEFAULT_GUEST_BLOB_MEM_FLAGS, MemoryRegionFlags};
use crate::mem::mgr::SandboxMemoryManager;
#[cfg(feature = "guest-counter")]
use crate::mem::shared_mem::HostSharedMemory;
use crate::mem::shared_mem::{ExclusiveSharedMemory, SharedMemory};
use crate::sandbox::SandboxConfiguration;
use crate::{MultiUseSandbox, Result, new_error};

#[cfg(any(crashdump, gdb))]
#[derive(Clone, Debug, Default)]
pub(crate) struct SandboxRuntimeConfig {
    #[cfg(crashdump)]
    pub(crate) binary_path: Option<String>,
    #[cfg(gdb)]
    pub(crate) debug_info: Option<super::config::DebugInfo>,
    #[cfg(crashdump)]
    pub(crate) guest_core_dump: bool,
    /// The original entry point address of the loaded guest binary
    /// (load_addr + ELF entry offset). Used for AT_ENTRY in core dumps
    /// so GDB can compute the correct load offset for PIE binaries.
    ///
    /// `None` until resolved from the snapshot's `NextAction::Initialise`
    /// in `set_up_hypervisor_partition`.
    #[cfg(crashdump)]
    pub(crate) entry_point: Option<u64>,
}

/// A host-authoritative shared counter exposed to the guest via a `u64`
/// in guest scratch memory.
///
/// Created via [`UninitializedSandbox::guest_counter()`]. The host owns
/// the counter value and is the only writer: [`increment()`](Self::increment)
/// and [`decrement()`](Self::decrement) update the cached value and write
/// to shared memory via [`HostSharedMemory::write()`]. [`value()`](Self::value)
/// returns the cached value — the host never reads back from guest memory,
/// so a malicious guest cannot influence the host's view of the counter.
///
/// Thread safety is provided by an internal `Mutex`, so `increment()` and
/// `decrement()` take `&self` rather than `&mut self`.
///
/// The counter holds an `Arc<Mutex<Option<HostSharedMemory>>>` that is
/// shared with [`UninitializedSandbox`]. The `Option` is `None` until
/// [`evolve()`](UninitializedSandbox::evolve) populates it, at which point
/// the counter can issue volatile writes via the proper protocol.
///
/// Only one `GuestCounter` may be created per sandbox; a second call to
/// [`UninitializedSandbox::guest_counter()`] returns an error.
#[cfg(feature = "guest-counter")]
pub struct GuestCounter {
    inner: Mutex<GuestCounterInner>,
}

#[cfg(feature = "guest-counter")]
struct GuestCounterInner {
    deferred_hshm: Arc<Mutex<Option<HostSharedMemory>>>,
    offset: usize,
    value: u64,
}

#[cfg(feature = "guest-counter")]
impl core::fmt::Debug for GuestCounter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GuestCounter").finish_non_exhaustive()
    }
}

#[cfg(feature = "guest-counter")]
impl GuestCounter {
    /// Increments the counter by one and writes it to guest memory.
    pub fn increment(&self) -> Result<()> {
        let mut inner = self.inner.lock().map_err(|e| new_error!("{e}"))?;
        let shm = {
            let guard = inner.deferred_hshm.lock().map_err(|e| new_error!("{e}"))?;
            guard
                .as_ref()
                .ok_or_else(|| {
                    new_error!("GuestCounter cannot be used before shared memory is built")
                })?
                .clone()
        };
        let new_value = inner
            .value
            .checked_add(1)
            .ok_or_else(|| new_error!("GuestCounter overflow"))?;
        shm.write::<u64>(inner.offset, new_value)?;
        inner.value = new_value;
        Ok(())
    }

    /// Decrements the counter by one and writes it to guest memory.
    pub fn decrement(&self) -> Result<()> {
        let mut inner = self.inner.lock().map_err(|e| new_error!("{e}"))?;
        let shm = {
            let guard = inner.deferred_hshm.lock().map_err(|e| new_error!("{e}"))?;
            guard
                .as_ref()
                .ok_or_else(|| {
                    new_error!("GuestCounter cannot be used before shared memory is built")
                })?
                .clone()
        };
        let new_value = inner
            .value
            .checked_sub(1)
            .ok_or_else(|| new_error!("GuestCounter underflow"))?;
        shm.write::<u64>(inner.offset, new_value)?;
        inner.value = new_value;
        Ok(())
    }

    /// Returns the current host-side value of the counter.
    pub fn value(&self) -> Result<u64> {
        let inner = self.inner.lock().map_err(|e| new_error!("{e}"))?;
        Ok(inner.value)
    }
}

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
    #[cfg(any(crashdump, gdb))]
    pub(crate) rt_cfg: SandboxRuntimeConfig,
    pub(crate) load_info: crate::mem::exe::LoadInfo,
    // This is needed to convey the stack pointer between the snapshot
    // and the HyperlightVm creation
    pub(crate) stack_top_gva: u64,
    /// Populated by [`evolve()`](Self::evolve) with a [`HostSharedMemory`]
    /// view of scratch memory. Code that needs host-style volatile access
    /// before `evolve()` (e.g. `GuestCounter`) can clone this `Arc` and
    /// will see `Some` once `evolve()` completes.
    #[cfg(feature = "guest-counter")]
    pub(crate) deferred_hshm: Arc<Mutex<Option<HostSharedMemory>>>,
    /// Set to `true` once a [`GuestCounter`] has been handed out via
    /// [`guest_counter()`](Self::guest_counter). Prevents creating
    /// multiple counters that would have divergent cached values.
    #[cfg(feature = "guest-counter")]
    counter_taken: std::sync::atomic::AtomicBool,
    /// File mappings prepared by [`Self::map_file_cow`] that will be
    /// applied to the VM during [`Self::evolve`].
    pub(crate) pending_file_mappings: Vec<super::file_mapping::PreparedFileMapping>,
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
    /// Creates a [`GuestCounter`] at a fixed offset in scratch memory.
    ///
    /// The counter lives at `SCRATCH_TOP_GUEST_COUNTER_OFFSET` bytes from
    /// the top of scratch memory, so both host and guest can locate it
    /// without an explicit GPA parameter.
    ///
    /// The returned counter holds an `Arc` clone of the sandbox's
    /// `deferred_hshm`, so it will automatically gain access to the
    /// [`HostSharedMemory`] once [`evolve()`](Self::evolve) completes.
    ///
    /// This method can only be called once; a second call returns an error
    /// because multiple counters would have divergent cached values.
    #[cfg(feature = "guest-counter")]
    pub fn guest_counter(&mut self) -> Result<GuestCounter> {
        use std::sync::atomic::Ordering;

        use hyperlight_common::layout::SCRATCH_TOP_GUEST_COUNTER_OFFSET;

        if self.counter_taken.swap(true, Ordering::Relaxed) {
            return Err(new_error!(
                "GuestCounter has already been created for this sandbox"
            ));
        }

        let scratch_size = self.mgr.scratch_mem.mem_size();
        if (SCRATCH_TOP_GUEST_COUNTER_OFFSET as usize) > scratch_size {
            return Err(new_error!(
                "scratch memory too small for guest counter (size {:#x}, need offset {:#x})",
                scratch_size,
                SCRATCH_TOP_GUEST_COUNTER_OFFSET,
            ));
        }

        let offset = scratch_size - SCRATCH_TOP_GUEST_COUNTER_OFFSET as usize;
        let deferred_hshm = self.deferred_hshm.clone();

        Ok(GuestCounter {
            inner: Mutex::new(GuestCounterInner {
                deferred_hshm,
                offset,
                value: 0,
            }),
        })
    }

    // Creates a new uninitialized sandbox from a pre-built snapshot.
    // Note that since memory configuration is part of the snapshot the only configuration
    // that can be changed (from the original snapshot) is the configuration defines the behaviour of
    // `InterruptHandler` on Linux.
    //
    // This is ok for now as this is not a public function
    fn from_snapshot(
        snapshot: Arc<Snapshot>,
        cfg: Option<SandboxConfiguration>,
        #[cfg(crashdump)] binary_path: Option<String>,
    ) -> Result<Self> {
        #[cfg(feature = "build-metadata")]
        log_build_details();

        // hyperlight is only supported on Windows 11 and Windows Server 2022 and later
        #[cfg(target_os = "windows")]
        check_windows_version()?;

        let sandbox_cfg = cfg.unwrap_or_default();

        #[cfg(any(crashdump, gdb))]
        let rt_cfg = {
            #[cfg(crashdump)]
            let guest_core_dump = sandbox_cfg.get_guest_core_dump();

            #[cfg(gdb)]
            let debug_info = sandbox_cfg.get_guest_debug_info();

            SandboxRuntimeConfig {
                #[cfg(crashdump)]
                binary_path,
                #[cfg(gdb)]
                debug_info,
                #[cfg(crashdump)]
                guest_core_dump,
                // entry_point is set later in set_up_hypervisor_partition
                // once the entrypoint is resolved from the snapshot
                #[cfg(crashdump)]
                entry_point: None,
            }
        };

        let mem_mgr_wrapper =
            SandboxMemoryManager::<ExclusiveSharedMemory>::from_snapshot(snapshot.as_ref())?;

        let host_funcs = Arc::new(Mutex::new(FunctionRegistry::default()));

        let mut sandbox = Self {
            host_funcs,
            mgr: mem_mgr_wrapper,
            max_guest_log_level: None,
            config: sandbox_cfg,
            #[cfg(any(crashdump, gdb))]
            rt_cfg,
            load_info: snapshot.load_info(),
            stack_top_gva: snapshot.stack_top_gva(),
            #[cfg(feature = "guest-counter")]
            deferred_hshm: Arc::new(Mutex::new(None)),
            #[cfg(feature = "guest-counter")]
            counter_taken: std::sync::atomic::AtomicBool::new(false),
            pending_file_mappings: Vec::new(),
        };

        // If we were passed a writer for host print register it otherwise use the default.
        sandbox.register_print(default_writer_func)?;

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
        #[cfg(crashdump)]
        let binary_path = match &env.guest_binary {
            GuestBinary::FilePath(path) => Some(path.clone()),
            GuestBinary::Buffer(_) => None,
        };
        let snapshot = Snapshot::from_env(env, cfg)?;
        Self::from_snapshot(
            Arc::new(snapshot),
            Some(cfg),
            #[cfg(crashdump)]
            binary_path,
        )
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

    /// Map the contents of a file into the guest at a particular address.
    ///
    /// The file mapping is prepared immediately (host-side OS work) but
    /// the actual VM-side mapping is deferred until [`evolve()`](Self::evolve).
    ///
    /// An optional `label` identifies this mapping in the PEB's
    /// `FileMappingInfo` array (max 63 bytes, defaults to the file name).
    ///
    /// The `guest_base` must be page-aligned and must lie **outside**
    /// the sandbox's primary shared memory region (`BASE_ADDRESS` to
    /// `BASE_ADDRESS + shared_mem_size`).
    ///
    /// Returns the length of the mapping in bytes.
    #[instrument(err(Debug), skip(self, file_path, guest_base, label), parent = Span::current())]
    pub fn map_file_cow(
        &mut self,
        file_path: &std::path::Path,
        guest_base: u64,
        label: Option<&str>,
    ) -> crate::Result<u64> {
        // Fail fast if the preallocated PEB array is already full.
        if self.pending_file_mappings.len() >= hyperlight_common::mem::MAX_FILE_MAPPINGS {
            return Err(crate::HyperlightError::Error(format!(
                "map_file_cow: file mapping limit reached ({} of {})",
                self.pending_file_mappings.len(),
                hyperlight_common::mem::MAX_FILE_MAPPINGS,
            )));
        }

        // Validate that guest_base is outside the sandbox's primary memory slot.
        // (Full range check happens after prepare_file_cow when we know the mapped size.)
        let shared_size = self.mgr.shared_mem.mem_size() as u64;
        let base_addr = crate::mem::layout::SandboxMemoryLayout::BASE_ADDRESS as u64;

        let prepared = super::file_mapping::prepare_file_cow(file_path, guest_base, label)?;

        // Validate full mapped range doesn't overlap shared memory.
        let mapping_end = guest_base
            .checked_add(prepared.size as u64)
            .ok_or_else(|| {
                crate::HyperlightError::Error(format!(
                    "map_file_cow: guest address overflow: {:#x} + {:#x}",
                    guest_base, prepared.size
                ))
            })?;
        let shared_end = base_addr.checked_add(shared_size).ok_or_else(|| {
            crate::HyperlightError::Error("shared memory end overflow".to_string())
        })?;
        if guest_base < shared_end && mapping_end > base_addr {
            return Err(crate::HyperlightError::Error(format!(
                "map_file_cow: mapping [{:#x}..{:#x}) overlaps sandbox shared memory [{:#x}..{:#x})",
                guest_base, mapping_end, base_addr, shared_end,
            )));
        }

        let size = prepared.size as u64;

        // Check for overlaps with existing pending file mappings.
        let new_start = guest_base;
        let new_end = mapping_end;
        for existing in &self.pending_file_mappings {
            let ex_start = existing.guest_base;
            let ex_end = ex_start.checked_add(existing.size as u64).ok_or_else(|| {
                crate::HyperlightError::Error(format!(
                    "map_file_cow: existing mapping address overflow: {:#x} + {:#x}",
                    ex_start, existing.size
                ))
            })?;
            if new_start < ex_end && new_end > ex_start {
                return Err(crate::HyperlightError::Error(format!(
                    "map_file_cow: mapping [{:#x}..{:#x}) overlaps existing mapping [{:#x}..{:#x})",
                    new_start, new_end, ex_start, ex_end,
                )));
            }
        }

        self.pending_file_mappings.push(prepared);
        Ok(size)
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
    /// defaulting to [`LevelFilter::Error`] if unset.
    pub fn set_max_guest_log_level(&mut self, log_level: LevelFilter) {
        self.max_guest_log_level = Some(log_level);
    }

    /// Registers a host function that the guest can call.
    pub fn register<Args: ParameterTuple, Output: SupportedReturnType>(
        &mut self,
        name: impl AsRef<str>,
        host_func: impl Into<HostFunction<Output, Args>>,
    ) -> Result<()> {
        register_host_function(host_func, self, name.as_ref())
    }

    /// Registers the special "HostPrint" function for guest printing.
    ///
    /// This overrides the default behavior of writing to stdout.
    /// The function expects the signature `FnMut(String) -> i32`
    /// and will be called when the guest wants to print output.
    pub fn register_print(
        &mut self,
        print_func: impl Into<HostFunction<i32, (String,)>>,
    ) -> Result<()> {
        self.register("HostPrint", print_func)
    }

    /// Populate the deferred `HostSharedMemory` slot without running
    /// the full `evolve()` pipeline. Used in tests where guest boot
    /// is not available.
    #[cfg(all(test, feature = "guest-counter"))]
    fn simulate_build(&self) {
        let hshm = self.mgr.scratch_mem.as_host_shared_memory();
        #[allow(clippy::unwrap_used)]
        {
            *self.deferred_hshm.lock().unwrap() = Some(hshm);
        }
    }
}
// Check to see if the current version of Windows is supported
// Hyperlight is only supported on Windows 11 and Windows Server 2022 and later
#[cfg(target_os = "windows")]
fn check_windows_version() -> Result<()> {
    use windows_version::{OsVersion, is_server};
    const WINDOWS_MAJOR: u32 = 10;
    const WINDOWS_MINOR: u32 = 0;
    const WINDOWS_PACK: u32 = 0;

    // Windows Server 2022 has version numbers 10.0.20348 or greater
    if is_server() {
        if OsVersion::current() < OsVersion::new(WINDOWS_MAJOR, WINDOWS_MINOR, WINDOWS_PACK, 20348)
        {
            return Err(new_error!(
                "Hyperlight Requires Windows Server 2022 or newer"
            ));
        }
    } else if OsVersion::current()
        < OsVersion::new(WINDOWS_MAJOR, WINDOWS_MINOR, WINDOWS_PACK, 22000)
    {
        return Err(new_error!("Hyperlight Requires Windows 11 or newer"));
    }
    Ok(())
}
