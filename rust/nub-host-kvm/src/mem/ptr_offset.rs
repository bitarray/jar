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

use std::cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd};
use std::convert::From;
use std::ops::{Add, Sub};

use tracing::{Span, instrument};

use crate::Result;
use crate::error::HyperlightError;

/// An offset into a given address space.
///
/// Use this type to distinguish between an offset and a raw pointer
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct Offset(u64);

impl Default for Offset {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn default() -> Self {
        Offset::from(0_u64)
    }
}

impl From<u64> for Offset {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn from(val: u64) -> Self {
        Self(val)
    }
}

impl From<&Offset> for u64 {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn from(val: &Offset) -> u64 {
        val.0
    }
}

impl From<Offset> for u64 {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn from(val: Offset) -> u64 {
        val.0
    }
}

impl TryFrom<Offset> for i64 {
    type Error = HyperlightError;
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn try_from(val: Offset) -> Result<i64> {
        Ok(i64::try_from(val.0)?)
    }
}

impl TryFrom<i64> for Offset {
    type Error = HyperlightError;
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn try_from(val: i64) -> Result<Offset> {
        let val_u64 = u64::try_from(val)?;
        Ok(Offset::from(val_u64))
    }
}

impl TryFrom<usize> for Offset {
    type Error = HyperlightError;
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn try_from(val: usize) -> Result<Offset> {
        Ok(u64::try_from(val).map(Offset::from)?)
    }
}

/// Convert an `Offset` to a `usize`, returning an `Err` if the
/// conversion couldn't be made.
impl TryFrom<&Offset> for usize {
    type Error = HyperlightError;
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn try_from(val: &Offset) -> Result<usize> {
        Ok(usize::try_from(val.0)?)
    }
}

impl TryFrom<Offset> for usize {
    type Error = HyperlightError;
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn try_from(val: Offset) -> Result<usize> {
        usize::try_from(&val)
    }
}

impl Add<Offset> for Offset {
    type Output = Offset;
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn add(self, rhs: Offset) -> Offset {
        Offset::from(self.0 + rhs.0)
    }
}

impl Add<usize> for Offset {
    type Output = Offset;
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn add(self, rhs: usize) -> Offset {
        Offset(self.0 + rhs as u64)
    }
}

impl Add<Offset> for usize {
    type Output = Offset;
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn add(self, rhs: Offset) -> Offset {
        rhs.add(self)
    }
}

impl Add<u64> for Offset {
    type Output = Offset;
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn add(self, rhs: u64) -> Offset {
        Offset(self.0 + rhs)
    }
}

impl Add<Offset> for u64 {
    type Output = Offset;
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn add(self, rhs: Offset) -> Offset {
        rhs.add(self)
    }
}

impl Sub<Offset> for Offset {
    type Output = Offset;
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn sub(self, rhs: Offset) -> Offset {
        Offset::from(self.0 - rhs.0)
    }
}

impl Sub<usize> for Offset {
    type Output = Offset;
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn sub(self, rhs: usize) -> Offset {
        Offset(self.0 - rhs as u64)
    }
}

impl Sub<Offset> for usize {
    type Output = Offset;
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn sub(self, rhs: Offset) -> Offset {
        rhs.sub(self)
    }
}

impl Sub<u64> for Offset {
    type Output = Offset;
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn sub(self, rhs: u64) -> Offset {
        Offset(self.0 - rhs)
    }
}

impl Sub<Offset> for u64 {
    type Output = Offset;
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn sub(self, rhs: Offset) -> Offset {
        rhs.sub(self)
    }
}

impl PartialEq<usize> for Offset {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn eq(&self, other: &usize) -> bool {
        match usize::try_from(self) {
            Ok(offset_usize) => offset_usize == *other,
            _ => false,
        }
    }
}

impl PartialOrd<usize> for Offset {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn partial_cmp(&self, rhs: &usize) -> Option<Ordering> {
        match usize::try_from(self) {
            Ok(offset_usize) if offset_usize > *rhs => Some(Ordering::Greater),
            Ok(offset_usize) if offset_usize == *rhs => Some(Ordering::Equal),
            Ok(_) => Some(Ordering::Less),
            Err(_) => None,
        }
    }
}

impl PartialEq<u64> for Offset {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn eq(&self, rhs: &u64) -> bool {
        u64::from(self) == *rhs
    }
}

impl PartialOrd<u64> for Offset {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn partial_cmp(&self, rhs: &u64) -> Option<Ordering> {
        let lhs: u64 = self.into();
        match lhs > *rhs {
            true => Some(Ordering::Greater),
            false if lhs == *rhs => Some(Ordering::Equal),
            false => Some(Ordering::Less),
        }
    }
}
