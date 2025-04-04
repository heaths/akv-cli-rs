// Copyright 2024 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

// cspell:disable
use crate::{Error, ErrorKind, Result};
use libc::openpty;
use std::{
    io::{self, Read},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    process::Stdio,
    ptr,
};

/// Open a pseudoterminal.
pub fn open() -> Result<(Pty, Pts)> {
    let mut pty = 0;
    let mut pts = 0;
    unsafe {
        let ret = openpty(
            &mut pty,
            &mut pts,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        if ret != 0 {
            return Err(Error::new(
                ErrorKind::Io,
                format!("failed to open pty: {ret}"),
            ));
        }

        Ok((
            Pty(OwnedFd::from_raw_fd(pty)),
            Pts(OwnedFd::from_raw_fd(pts)),
        ))
    }
}

/// A pseudoterminal.
#[derive(Debug)]
pub struct Pty(OwnedFd);

impl Read for Pty {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = unsafe {
            libc::read(
                self.0.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };

        if len == -1 {
            return Err(io::Error::last_os_error());
        }

        Ok(len as usize)
    }
}

/// The child end of a pseudoterminal.
#[derive(Debug)]
pub struct Pts(OwnedFd);

impl TryFrom<&Pts> for Stdio {
    type Error = io::Error;
    fn try_from(pts: &Pts) -> std::result::Result<Self, Self::Error> {
        Ok(pts.0.try_clone()?.into())
    }
}
