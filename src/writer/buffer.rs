// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use std::io::{self, Write};

/// A fixed vector to keep track of length as we read and write.
pub struct Buffer<const N: usize> {
    inner: [u8; N],
    len: usize,
}

impl<const N: usize> Buffer<N> {
    pub fn new() -> Self {
        Self {
            inner: [0; N],
            len: 0,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.inner[..self.len]
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

impl<const N: usize> Write for Buffer<N> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let available = N - self.len;
        let over = buf.len() as isize - available as isize;

        if over > 0 {
            let written = available;
            self.inner[self.len..N].copy_from_slice(&buf[..written]);
            self.len += written;

            return Ok(written);
        }

        let written = buf.len();
        self.inner[self.len..self.len + written].copy_from_slice(&buf[..written]);
        self.len += written;

        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        panic!("unexpected")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn too_large() {
        let mut buf = Buffer::<30>::new();
        let written = buf.write(b"Hello, world!").unwrap();
        assert_eq!(written, 13);
        assert_eq!(&buf.inner[..written], b"Hello, world!");
        assert_eq!(buf.len(), 13);

        let written = buf.write(b" And space folk!").unwrap();
        assert_eq!(written, 16);
        assert_eq!(&buf.inner.as_slice(), b"Hello, world! And space folk!\0");
        assert_eq!(buf.len(), 29);
    }

    #[test]
    fn too_small() {
        let mut buf = Buffer::<10>::new();
        let written = buf.write(b"Hello, world!").unwrap();
        assert_eq!(written, 10);
        assert_eq!(&buf.inner, b"Hello, wor");
        assert_eq!(buf.len(), 10);
    }

    #[test]
    fn just_right() {
        let mut buf = Buffer::new();
        let written = buf.write(b"Hello, world!").unwrap();
        assert_eq!(written, 13);
        assert_eq!(&buf.inner, b"Hello, world!");
        assert_eq!(buf.len(), 13);

        let written = buf.write(b"No room").unwrap();
        assert_eq!(written, 0);
        assert_eq!(&buf.inner, b"Hello, world!");
        assert_eq!(buf.len(), 13);
    }
}
