// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

#[cfg(feature = "color")]
use crate::color;
use crate::ColorMode;
use serde::Serialize;
use std::io::{stdout, IsTerminal as _};

pub fn print<T: Serialize>(
    value: &T,
    #[allow(unused_variables)] mode: ColorMode,
) -> crate::Result<()> {
    #[cfg(feature = "color")]
    {
        use colored_json::Styler;

        let styler: Styler = color::Config::from_env().into();
        match stdout().is_terminal() {
            false => {
                let mut stdout = stdout();
                colored_json::ColoredFormatter::with_styler(
                    serde_json::ser::CompactFormatter,
                    styler,
                )
                .write_colored_json(value, &mut stdout, mode.into())?;

                Ok(())
            }
            true => {
                use std::io::Write as _;

                let mut stdout = stdout();
                colored_json::ColoredFormatter::with_styler(
                    serde_json::ser::PrettyFormatter::new(),
                    styler,
                )
                .write_colored_json(value, &mut stdout, mode.into())?;
                writeln!(&mut stdout)?;

                Ok(())
            }
        }
    }

    #[cfg(not(feature = "color"))]
    match stdout().is_terminal() {
        false => Ok(serde_json::to_writer(stdout(), value)?),
        true => {
            use std::io::Write as _;

            let mut stdout = stdout();
            serde_json::to_writer_pretty(&stdout, value)?;
            writeln!(&mut stdout)?;

            Ok(())
        }
    }
}

#[cfg(feature = "color")]
impl From<ColorMode> for colored_json::ColorMode {
    fn from(value: ColorMode) -> Self {
        match value {
            ColorMode::Always => Self::On,
            ColorMode::Auto => Self::Auto(colored_json::Output::StdOut),
            ColorMode::Never => Self::Off,
        }
    }
}
