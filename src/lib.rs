// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

#![cfg_attr(windows, feature(windows_process_extensions_raw_attribute))]

pub mod cache;
mod error;
pub mod parsing;
pub mod pty;

use async_stream::try_stream;
use azure_core::http::{Model, Pager};
use azure_security_keyvault_secrets::models::{ListSecretPropertiesResult, SecretProperties};
pub use error::*;
use futures::{Stream, StreamExt as _};
use std::pin::Pin;

pub trait Page<T> {
    fn items(self) -> impl Iterator<Item = T>;
}

impl Page<SecretProperties> for ListSecretPropertiesResult {
    fn items(self) -> impl Iterator<Item = SecretProperties> {
        self.value.into_iter()
    }
}

pub fn list_items<R, T, F, E>(f: F) -> Pin<Box<impl Stream<Item = Result<T>>>>
where
    R: Model + Page<T>,
    F: AsyncFn() -> std::result::Result<Pager<R>, E>,
    E: Into<Error>,
{
    Box::pin(try_stream! {
        let mut pager = f().await?;
        while let Some(page) = pager.next().await {
            let result = page?.into_body().await?;
            for item in result.items() {
                yield item;
            }
        }
    })
}
