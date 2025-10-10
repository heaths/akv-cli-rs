// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

pub mod cache;
#[cfg(feature = "color")]
pub mod color;
pub mod credentials;
mod error;
pub mod jose;
pub mod json;
pub mod parsing;

pub use error::*;

/// Whether to write color attributes to the terminal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ColorMode {
    /// Write color attributes if `stdout` is a TTY and color is not otherwise disabled.
    #[default]
    Auto,

    /// Always write color attributes.
    Always,

    /// Never write color attributes.
    Never,
}
