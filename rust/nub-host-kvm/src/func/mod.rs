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

//! Host-side guest↔host RPC types.
//!
//! After the FB+SCALE → rkyv migration this module is a thin
//! re-export of [`HostFn`] (the boxed `FnMut(&[u8]) -> Result<Vec<u8>>`
//! signature every host function shares) + [`Registerable`] (the
//! trait that exposes `register_host_function(fn_id, hf)` on
//! `Uninitialized`/`MultiUse` sandboxes).

pub(crate) mod host_functions;

pub use crate::sandbox::host_funcs::HostFn;
pub use host_functions::Registerable;
