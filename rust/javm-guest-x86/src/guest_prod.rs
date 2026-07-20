//! Production guest function table for the Javm personality. The wrappers
//! and their linkme registrations are stamped by
//! [`nub_arch_x86::register_guest_kernel!`]; the generic bodies live in
//! [`nub_arch_x86::guest_fns`].

nub_arch_x86::register_guest_kernel!(crate::call_loop::Javm);
