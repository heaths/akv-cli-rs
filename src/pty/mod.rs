// Copyright 2024 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

#[cfg(not(windows))]
mod posix;
mod windows;

#[cfg(not(windows))]
use posix as inner;
use std::{
    io::{self, IsTerminal, Read},
    process::{Child, Command, Stdio},
};

#[derive(Debug)]
pub struct Pty(inner::Pty);

impl Read for Pty {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

pub trait CommandExt: __private::Sealed {
    type Output;
    fn spawn_pty(&mut self) -> crate::Result<(Self::Output, Pty)>;
}

impl CommandExt for Command {
    type Output = Child;
    fn spawn_pty(&mut self) -> crate::Result<(Self::Output, Pty)> {
        #[cfg(not(windows))]
        {
            let (pty, ref pts) = posix::open()?;
            if io::stdout().is_terminal() {
                self.stdout::<Stdio>(pts.try_into()?);
            }
            if io::stderr().is_terminal() {
                self.stderr::<Stdio>(pts.try_into()?);
            }

            Ok((self.spawn()?, Pty(pty)))
        }

        #[cfg(windows)]
        todo!()
    }
}

mod __private {
    pub trait Sealed {}
    impl Sealed for std::process::Command {}
}
