// Copyright 2024 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

// cspell:disable
use libc::{fcntl, openpty, F_GETFL, F_SETFL, O_NONBLOCK};
use std::{
    io::{self, IsTerminal as _, Read},
    os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    process::{Child, Command, Stdio},
    ptr,
};

impl super::CommandExt for Command {
    type Output = Child;

    fn spawn_pty<'a>(&mut self) -> crate::Result<(Self::Output, super::Pty<'a>)> {
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
                Err(io::Error::last_os_error())?;
            }

            let mut flags = fcntl(pty, F_GETFL);
            flags |= O_NONBLOCK;
            let ret = fcntl(pty, F_SETFL, flags);
            if ret != 0 {
                Err(io::Error::last_os_error())?;
            }

            let pty = Pty::Owned(OwnedFd::from_raw_fd(pty));
            let pts = Pts(OwnedFd::from_raw_fd(pts));

            if io::stdout().is_terminal() {
                self.stdout::<Stdio>(pts.0.try_clone()?.into());
            }
            if io::stderr().is_terminal() {
                self.stderr::<Stdio>(pts.0.try_clone()?.into());
            }

            Ok((self.spawn()?, super::Pty(pty)))
        }
    }
}

/// A pseudoterminal.
#[derive(Debug)]
pub enum Pty<'a> {
    Owned(OwnedFd),
    Borrowed(BorrowedFd<'a>),
}

impl AsRawFd for Pty<'_> {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        match self {
            Self::Owned(fd) => fd.as_raw_fd(),
            Self::Borrowed(fd) => fd.as_raw_fd(),
        }
    }
}

impl Clone for Pty<'_> {
    fn clone(&self) -> Self {
        unsafe { Self::Borrowed(BorrowedFd::borrow_raw(self.as_raw_fd())) }
    }
}

impl Read for Pty<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = unsafe {
            libc::read(
                self.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };

        if len == -1 {
            let err = io::Error::last_os_error();
            tracing::trace!("read error {err:?}");

            if let Some(libc::EBADF) = err.raw_os_error() {
                return Ok(0);
            }

            return Err(err);
        }

        Ok(len as usize)
    }
}

/// The child end of a pseudoterminal.
#[derive(Debug)]
pub struct Pts(OwnedFd);
