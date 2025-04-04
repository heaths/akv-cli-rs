// Copyright 2024 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

// cspell:disable
use crate::{Error, ErrorKind, Result};
use libc::{fcntl, grantpt, posix_openpt, unlockpt, F_GETFD, F_SETFD, O_CLOEXEC, O_NOCTTY, O_RDWR};
use std::{
    ffi::CString,
    fs::OpenOptions,
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::OpenOptionsExt,
    },
    process::Stdio,
};

/// Open a pseudoterminal.
pub fn open() -> Result<(Pty, Pts)> {
    unsafe {
        let pty = posix_openpt(O_RDWR | O_NOCTTY);
        if pty == -1 {
            return Err(Error::new(
                ErrorKind::Io,
                format!("failed to open pty: {pty}"),
            ));
        }

        let ret = grantpt(pty);
        if ret != 0 {
            return Err(Error::new(
                ErrorKind::Io,
                format!("failed to grant access to pty: {ret}"),
            ));
        }

        let ret = unlockpt(pty);
        if ret != 0 {
            return Err(Error::new(
                ErrorKind::Io,
                format!("failed to unlock pty: {ret}"),
            ));
        }

        let mut flags = fcntl(pty, F_GETFD);
        flags |= O_CLOEXEC;
        let ret = fcntl(pty, F_SETFD, flags);
        if ret != 0 {
            return Err(Error::new(
                ErrorKind::Io,
                format!("failed to update pty: {ret}"),
            ));
        }

        let ptsname = libc::ptsname(pty);
        if ptsname.is_null() {
            return Err(Error::new(ErrorKind::Io, "failed to get pty name"));
        }

        let ptsname: CString = CString::from_raw(ptsname);
        let ptsname = ptsname
            .into_string()
            .map_err(|err| Error::new(ErrorKind::Io, err))?;
        let pts: OwnedFd = OpenOptions::new()
            // .read(true)
            .write(true)
            .custom_flags(O_NOCTTY)
            .open(ptsname)?
            .into();

        Ok((Pty(OwnedFd::from_raw_fd(pty)), Pts(pts)))
    }
}

/// A pseudoterminal.
#[derive(Debug)]
pub struct Pty(OwnedFd);

impl Read for Pty {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let len = libc::read(self.0.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len());
            if len == -1 {
                return Err(io::Error::last_os_error());
            }

            Ok(len as usize)
        }
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
