// Copyright 2024 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

// cspell:ignore pseudoconsole
#[cfg(not(windows))]
mod posix;
#[cfg(windows)]
mod windows;

#[cfg(not(windows))]
use posix as inner;
use std::{
    fmt,
    io::{self, Read},
};
#[cfg(windows)]
use windows as inner;

#[derive(Clone)]
pub struct Pty<'a>(inner::Pty<'a>);

impl fmt::Debug for Pty<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format the inner directly instead of in a tuple.
        self.0.fmt(f)
    }
}

impl Read for Pty<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

pub trait CommandExt: __private::Sealed {
    type Output;
    fn spawn_pty<'a>(&mut self) -> crate::Result<(Self::Output, Pty<'a>)>;
}

mod __private {
    pub trait Sealed {}
    impl Sealed for std::process::Command {}
}
