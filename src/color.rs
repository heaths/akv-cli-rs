// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

//! Color configuration when feature `color` is enabled (default).

use colored_json::Styler;
use std::env;
use yansi::{Attribute, Color};

/// Color configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config([u16; 8]);

impl Config {
    /// Loads the `Config` from the environment.
    ///
    /// Currently only parses the [`JQ_COLORS`](https://jqlang.org/manual/#colors) environment variable.
    pub fn from_env() -> Self {
        env::var("JQ_COLORS")
            .ok()
            .and_then(Config::from_jq)
            .unwrap_or_default()
    }

    fn from_jq<S: AsRef<str>>(s: S) -> Option<Self> {
        let s = s.as_ref();
        let segments: Vec<&str> = s.split(':').collect();

        // Must have exactly 8 segments
        if segments.len() != 8 {
            return None;
        }

        let mut colors = [0u16; 8];
        for (i, segment) in segments.iter().enumerate() {
            let parts: Vec<&str> = segment.split(';').collect();

            // Each segment must have exactly 2 parts (style;color)
            if parts.len() != 2 {
                return None;
            }

            // Parse style and color
            let style: u8 = parts[0].parse().ok()?;
            let color_code: u8 = parts[1].parse().ok()?;

            // Map color codes: 30-37 → 0-7, 90-97 → 8-15, 39 → 16 (default)
            let color = match color_code {
                30..=37 => color_code - 30,     // 30-37 maps to 0-7
                39 => 16,                       // 39 maps to 16 (default)
                90..=97 => color_code - 90 + 8, // 90-97 maps to 8-15
                _ => return None,               // Invalid color code
            };

            // Combine style (upper 8 bits) with color (lower 8 bits)
            colors[i] = ((style as u16) << 8) | (color as u16);
        }

        Some(Self(colors))
    }

    /// Gets the color for null.
    pub fn null(&self) -> Style {
        Style(self.0[0])
    }

    /// Gets the color for false.
    pub fn r#false(&self) -> Style {
        Style(self.0[1])
    }

    /// Gets the color for true.
    pub fn r#true(&self) -> Style {
        Style(self.0[2])
    }

    /// Gets the color for numbers.
    pub fn numbers(&self) -> Style {
        Style(self.0[3])
    }

    /// Gets the color for strings.
    pub fn strings(&self) -> Style {
        Style(self.0[4])
    }

    /// Gets the color for arrays.
    pub fn arrays(&self) -> Style {
        Style(self.0[5])
    }

    /// Gets the color for objects.
    pub fn objects(&self) -> Style {
        Style(self.0[6])
    }

    /// Gets the color for object keys.
    pub fn object_keys(&self) -> Style {
        Style(self.0[7])
    }
}

impl Default for Config {
    fn default() -> Self {
        // Default equivalent to "0;90:0;39:0;39:0;39:0;32:1;39:1;39:1;34"
        // from https://jqlang.org/manual/#colors
        Self([8, 16, 16, 16, 2, 272, 272, 260])
    }
}

impl From<Config> for Styler {
    fn from(config: Config) -> Self {
        Self {
            object_brackets: config.objects().into(),
            object_colon: config.objects().into(),
            array_brackets: config.arrays().into(),
            key: config.object_keys().into(),
            string_value: config.strings().into(),
            integer_value: config.numbers().into(),
            float_value: config.numbers().into(),
            bool_value: config.r#false().into(),
            nil_value: config.null().into(),
            string_include_quotation: true,
        }
    }
}

/// Effects and foreground color.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Style(u16);

impl Style {
    fn attribute(&self) -> Option<Attribute> {
        // Only supports what jq supports.
        let effects: u8 = (self.0 >> 8) as u8;
        match effects {
            1 => Some(Attribute::Bold),
            2 => Some(Attribute::Dim),
            4 => Some(Attribute::Underline),
            5 => Some(Attribute::Blink),
            7 => Some(Attribute::Invert),
            8 => Some(Attribute::Conceal),
            _ => None,
        }
    }

    fn color(&self) -> Color {
        let fg = self.0 as u8;
        match fg {
            16 => Color::Primary,
            _ => Color::Fixed(fg),
        }
    }
}

impl From<Style> for colored_json::Style {
    fn from(value: Style) -> Self {
        let mut style = colored_json::Style::new().fg(value.color());
        if let Some(attr) = value.attribute() {
            style = style.attr(attr);
        }
        style
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_jq_matches_default() {
        assert_eq!(
            Config::from_jq("0;90:0;39:0;39:0;39:0;32:1;39:1;39:1;34"),
            Some(Config::default()),
        );
    }
}
