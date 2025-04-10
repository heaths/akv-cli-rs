// Copyright 2024 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

#![allow(non_camel_case_types, clippy::upper_case_acronyms)]

// cspell:ignore hpcon hresult pseudoconsole
use crate::{Error, ErrorKind};
use std::{
    cmp, fmt, io,
    marker::PhantomData,
    mem,
    os::windows::{
        io::AsRawHandle as _,
        process::{CommandExt as _, ProcThreadAttributeList},
        raw::HANDLE,
    },
    process::{Child, Command},
    ptr,
};

type DWORD = libc::c_uint;
type HPCON = HANDLE;

impl super::CommandExt for Command {
    type Output = Child;

    fn spawn_pty<'a>(&mut self) -> crate::Result<(Self::Output, super::Pty<'a>)> {
        unsafe {
            let mut input_read = mem::zeroed();
            let mut input_write = mem::zeroed();
            let mut output_read = mem::zeroed();
            let mut output_write = mem::zeroed();

            if ffi::CreatePipe(
                &mut input_read as *mut HANDLE,
                &mut input_write as *mut HANDLE,
                ptr::null(),
                0,
            )
            .is_err()
            {
                return Err(Error::new(ErrorKind::Io, io::Error::last_os_error()));
            }

            if ffi::CreatePipe(
                &mut output_read as *mut HANDLE,
                &mut output_write as *mut HANDLE,
                ptr::null(),
                0,
            )
            .is_err()
            {
                return Err(Error::new(ErrorKind::Io, io::Error::last_os_error()));
            }

            let mut info = mem::zeroed();
            if ffi::GetConsoleScreenBufferInfo(io::stdout().as_raw_handle(), &mut info).is_err() {
                return Err(Error::new(ErrorKind::Io, io::Error::last_os_error()));
            }

            let mut console_handle = mem::zeroed();
            let hr = ffi::CreatePseudoConsole(
                info.size,
                input_read,
                output_write,
                0,
                &mut console_handle,
            );
            if hr.is_err() {
                return Err(Error::new(
                    ErrorKind::Io,
                    format!("failed to create PTY: {hr}"),
                ));
            }

            // Close handles that were dup'd in CreatePseudoConsole.
            ffi::CloseHandle(input_read);
            ffi::CloseHandle(output_write);

            const PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE: usize = 0x20016;
            let attributes = ProcThreadAttributeList::build()
                .raw_attribute(
                    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                    console_handle as *const libc::c_void,
                    size_of::<isize>(),
                )
                .finish()?;
            let child = self.spawn_with_attributes(&attributes)?;

            Ok((
                child,
                super::Pty(Pty {
                    console_handle,
                    read_handle: output_read,
                    write_handle: input_write,
                    _phantom: PhantomData,
                }),
            ))
        }
    }
}

#[derive(Clone, Debug)]
pub struct Pty<'a> {
    console_handle: HPCON,
    read_handle: HANDLE,
    write_handle: HANDLE,
    _phantom: PhantomData<&'a Self>,
}

// A handle can safely be sent to another thread.
unsafe impl Send for Pty<'_> {}
unsafe impl Sync for Pty<'_> {}

impl Drop for Pty<'_> {
    fn drop(&mut self) {
        unsafe {
            ffi::ClosePseudoConsole(self.console_handle);

            // Must close the write handle before the read handle to terminate the pipe.
            ffi::CloseHandle(self.write_handle);
            ffi::CloseHandle(self.read_handle);
        };
    }
}

impl io::Read for Pty<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = cmp::min(buf.len(), u32::MAX as usize) as u32;
        let mut read = 0u32;
        unsafe {
            if ffi::ReadFile(
                self.read_handle,
                buf.as_mut_ptr().cast::<u8>(),
                len,
                &mut read,
                ptr::null_mut(),
            )
            .is_err()
            {
                let err = io::Error::last_os_error();
                tracing::trace!("read error {err:?}");

                const ERROR_INVALID_HANDLE: i32 = 6;
                if let Some(ERROR_INVALID_HANDLE) = err.raw_os_error() {
                    return Ok(0);
                }

                return Err(err);
            }
        }

        Ok(read as usize)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
struct BOOL(libc::c_int);

impl BOOL {
    fn is_err(self) -> bool {
        self.0 == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(transparent)]
struct HRESULT(i32);

impl HRESULT {
    fn is_err(self) -> bool {
        self.0 < 0
    }
}

impl fmt::Display for HRESULT {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08x}", self.0)
    }
}

mod ffi {
    use super::*;

    type SHORT = libc::c_short;

    unsafe extern "system" {
        pub unsafe fn CloseHandle(hObject: HANDLE) -> BOOL;

        pub unsafe fn ClosePseudoConsole(hPC: HPCON);

        pub unsafe fn CreatePipe(
            hReadPipe: *mut HANDLE,
            hWritePipe: *mut HANDLE,
            lpPipeAttributes: *const libc::c_void,
            nSize: DWORD,
        ) -> BOOL;

        pub unsafe fn CreatePseudoConsole(
            size: COORD,
            hInput: HANDLE,
            hOutput: HANDLE,
            dwFlags: DWORD,
            phPC: *mut HPCON,
        ) -> HRESULT;

        pub unsafe fn GetConsoleScreenBufferInfo(
            hConsoleOutput: HANDLE,
            lpConsoleScreenBufferInfo: *mut CONSOLE_SCREEN_BUFFER_INFO,
        ) -> BOOL;

        pub unsafe fn ReadFile(
            hFile: HANDLE,
            lpBuffer: *mut u8,
            nNumberOfBytesToRead: DWORD,
            lpNumberOfBytesRead: *mut DWORD,
            lpOverlapped: *mut libc::c_void,
        ) -> BOOL;
    }

    #[repr(C)]
    pub struct COORD {
        pub x: SHORT,
        pub y: SHORT,
    }

    #[repr(C)]
    pub struct CONSOLE_SCREEN_BUFFER_INFO {
        pub size: COORD,
        cursor_position: COORD,
        attributes: u16,
        left: i16,
        top: i16,
        right: i16,
        bottom: i16,
        max_window_size: COORD,
    }
}
