// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

mod buffer;

use buffer::*;
use std::io::{self, Read, Write};

const DEFAULT_BUF_SIZE: usize = 0x2000;

pub struct LineWriter<W: Write + ?Sized, F, const N: usize = DEFAULT_BUF_SIZE> {
    buffer: Buffer<N>,
    replace_fn: F,
    inner: W,
}

impl<W, F, const N: usize> LineWriter<W, F, N>
where
    W: Write,
    F: Fn(&str) -> String,
{
    pub fn new(inner: W, replace: F) -> Self {
        Self {
            buffer: Buffer::new(),
            replace_fn: replace,
            inner,
        }
    }
}

impl<W, F> LineWriter<W, F>
where
    W: Write + ?Sized,
    F: Fn(&str) -> String,
{
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    fn replace(&self, line: &str) -> String {
        (self.replace_fn)(line)
    }
}

impl<W, F, const N: usize> Write for LineWriter<W, F, N>
where
    W: Write + ?Sized,
    F: Fn(&str) -> String,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        todo!()
    }

    fn flush(&mut self) -> io::Result<()> {
        // Drain the remaining contents of the buffer.
        todo!()
    }
}
