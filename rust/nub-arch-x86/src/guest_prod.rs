//! Production guest function table for the Javm personality. The wrappers
//! and their linkme registrations are stamped by
//! [`crate::register_guest_kernel!`]; the generic bodies live in
//! [`crate::guest_fns`].

crate::register_guest_kernel!(crate::call_loop::Javm);
