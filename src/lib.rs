// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

// cspell:ignore docsrs
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

pub mod cache;
#[cfg(feature = "color")]
pub mod color;
mod error;
pub mod jose;
pub mod json;
pub mod parsing;

use std::borrow::Cow;

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

impl ColorMode {
    /// Whether ANSI color is enabled.
    pub fn enabled(&self) -> bool {
        #[cfg(feature = "color")]
        {
            use yansi::Condition;

            match self {
                ColorMode::Always => true,
                ColorMode::Auto => Condition::tty_and_color(),
                ColorMode::Never => false,
            }
        }

        #[cfg(not(feature = "color"))]
        false
    }

    /// Gets a [`Style`] based on this `ColorMode`.
    pub fn style(&self) -> Style {
        Style(*self)
    }
}

/// Styles text depending on the [`ColorMode`].
pub struct Style(#[cfg_attr(not(feature = "color"), allow(dead_code))] ColorMode);

impl Style {
    /// Conditionally colors the `message`.
    pub fn error<'a>(&self, message: &'a str) -> Cow<'a, str> {
        #[cfg(feature = "color")]
        {
            use yansi::{Color, Paint, Style};

            static STYLE: Style = Color::Red.bold();

            if self.0.enabled() {
                return Cow::Owned(message.paint(STYLE).to_string());
            }

            Cow::Borrowed(message)
        }

        #[cfg(not(feature = "color"))]
        Cow::Borrowed(message)
    }
}
