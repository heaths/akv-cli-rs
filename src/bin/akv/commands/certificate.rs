// Copyright 2025 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

use super::{elapsed, VAULT_ENV_NAME};
use crate::{
    commands::{
        key::{CurveName, KeySize, KeyType},
        map_tags, map_vec, AttributeArgs, IsDefault,
    },
    credential, TableExt,
};
use akv_cli::{json, parsing::parse_key_value_opt, Error, ErrorKind, Result};
use azure_core::{http::Url, time::OffsetDateTime, Bytes};
use azure_security_keyvault_certificates::{
    models::{
        Certificate, CertificateAttributes, CertificateClientGetCertificateOptions,
        CertificateClientUpdateCertificatePropertiesOptions, CertificatePolicy,
        CertificateProperties, CreateCertificateParameters, IssuerParameters, KeyProperties,
        UpdateCertificatePropertiesParameters, X509CertificateProperties,
    },
    CertificateClient, ResourceExt as _, ResourceId,
};
use clap::{ArgAction, Subcommand, ValueEnum};
use futures::TryStreamExt as _;
use indicatif::ProgressBar;
use prettytable::{color, format, Attr, Cell, Row, Table};
use std::{fmt, time::Duration};
use timeago::Formatter;
use tracing::{Level, Span};

// clap doesn't support global, required arguments so we have to put `vault` into each subcommand.

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Create certificates in an Azure Key Vault.
    Create {
        /// Name of the certificate.
        #[arg(long)]
        name: String,

        /// The vault URL e.g., "https://my-vault.vault.azure.net".
        #[arg(long, value_name = "URL", env = VAULT_ENV_NAME)]
        vault: Url,

        /// The certificate issuer name.
        #[arg(long, default_value = "Self")]
        issuer: String,

        /// The subject name.
        #[arg(long, default_value = "CN=DefaultPolicy")]
        subject: String,

        /// How many months the certificate is valid.
        #[arg(long, default_value_t = 3)]
        validity: u32,

        /// The key type.
        #[arg(id = "type", long, value_enum)]
        r#type: KeyType,

        /// The key size in bits for RSA keys.
        #[arg(long, value_parser, required_if_eq("type", "rsa"))]
        size: Option<KeySize>,

        /// The elliptic curve name for EC keys.
        #[arg(long, value_enum, required_if_eq("type", "ec"))]
        curve: Option<CurveName>,

        /// Set the private key as exportable.
        #[arg(long, action = ArgAction::SetTrue, default_value_t = false)]
        exportable: bool,

        /// Reuse the same key pair when renewing the certificate.
        #[arg(long, action = ArgAction::SetTrue, default_value_t = false)]
        reuse_key: bool,

        /// Key usage type.
        #[arg(long, value_enum, value_delimiter = ',')]
        key_usage: Vec<KeyUsageType>,

        /// Enhanced key usage OIDs.
        #[arg(long, value_delimiter = ',')]
        enhanced_key_usage: Vec<String>,

        #[command(flatten)]
        attributes: AttributeArgs,

        /// Tags to set on the certificate formatted as "name[=value]".
        /// Repeat argument once for each tag.
        #[arg(long, value_name = "NAME[=VALUE]", value_parser = parse_key_value_opt::<String>)]
        tags: Vec<(String, Option<String>)>,
    },

    /// Edits a certificate in an Azure Key Vault.
    Edit {
        /// The certificate URL e.g., "https://my-vault.vault.azure.net/certificate/my-certificate".
        #[arg(group = "ident", value_name = "URL")]
        id: Option<Url>,

        /// The certificate name.
        #[arg(long, group = "ident", requires = "vault")]
        name: Option<String>,

        /// The vault URL e.g., "https://my-vault.vault.azure.net".
        #[arg(long, value_name = "URL", env = VAULT_ENV_NAME)]
        vault: Option<Url>,

        #[command(flatten)]
        attributes: AttributeArgs,

        /// Tags to set on the certificate formatted as "name[=value]".
        /// Repeat argument once for each tag.
        #[arg(long, value_name = "NAME[=VALUE]", value_parser = parse_key_value_opt::<String>)]
        tags: Vec<(String, Option<String>)>,
    },

    /// Edits the certificate policy for the next certificate request.
    EditPolicy {
        /// The certificate URL e.g., "https://my-vault.vault.azure.net/certificate/my-certificate".
        #[arg(group = "ident", value_name = "URL")]
        id: Option<Url>,

        /// The certificate name.
        #[arg(long, group = "ident", requires = "vault")]
        name: Option<String>,

        /// The vault URL e.g., "https://my-vault.vault.azure.net".
        #[arg(long, value_name = "URL", env = VAULT_ENV_NAME)]
        vault: Option<Url>,

        /// The certificate issuer name.
        #[arg(long)]
        issuer: Option<String>,

        /// The subject name.
        #[arg(long)]
        subject: Option<String>,

        /// How many months the certificate is valid.
        #[arg(long)]
        validity: Option<u32>,

        /// The key type.
        #[arg(id = "type", long, value_enum)]
        r#type: Option<KeyType>,

        /// The key size in bits for RSA keys.
        #[arg(long, value_parser, required_if_eq("type", "rsa"))]
        size: Option<KeySize>,

        /// The elliptic curve name for EC keys.
        #[arg(long, value_enum, required_if_eq("type", "ec"))]
        curve: Option<CurveName>,

        /// Set the private key as exportable.
        #[arg(long, action = ArgAction::SetTrue)]
        exportable: Option<bool>,

        /// Reuse the same key pair when renewing the certificate.
        #[arg(long, action = ArgAction::SetTrue)]
        reuse_key: Option<bool>,

        /// Key usage type.
        #[arg(long, value_enum, value_delimiter = ',')]
        key_usage: Option<Vec<KeyUsageType>>,

        /// Enhanced key usage OIDs.
        #[arg(long, value_delimiter = ',')]
        enhanced_key_usage: Option<Vec<String>>,
    },

    /// Gets information about a certificate in an Azure Key Vault.
    Get {
        /// The certificate URL e.g., "https://my-vault.vault.azure.net/certificates/my-certificate".
        #[arg(group = "ident", value_name = "URL")]
        id: Option<Url>,

        /// The certificate name.
        #[arg(long, group = "ident", requires = "vault")]
        name: Option<String>,

        /// The vault URL e.g., "https://my-vault.vault.azure.net".
        #[arg(long, value_name = "URL", env = VAULT_ENV_NAME)]
        vault: Option<Url>,
    },

    /// Gets the certificate policy for the next version of a certificate created in an Azure Key Vault.
    GetPolicy {
        /// The certificate URL e.g., "https://my-vault.vault.azure.net/certificates/my-certificate".
        #[arg(group = "ident", value_name = "URL")]
        id: Option<Url>,

        /// The certificate name.
        #[arg(long, group = "ident", requires = "vault")]
        name: Option<String>,

        /// The vault URL e.g., "https://my-vault.vault.azure.net".
        #[arg(long, value_name = "URL", env = VAULT_ENV_NAME)]
        vault: Option<Url>,
    },

    /// List certificate in an Azure Key Vault.
    List {
        /// The vault URL e.g., "https://my-vault.vault.azure.net".
        #[arg(long, value_name = "URL", env = VAULT_ENV_NAME)]
        vault: Url,

        /// Show more details about each certificate.
        #[arg(long)]
        long: bool,
    },

    /// List versions of a certificate in an Azure Key Vault.
    ListVersions {
        /// The certificate URL e.g., "https://my-vault.vault.azure.net/certificates/my-certificate".
        #[arg(group = "ident", value_name = "URL")]
        id: Option<Url>,

        /// The certificate name.
        #[arg(long, group = "ident", requires = "vault")]
        name: Option<String>,

        /// The vault URL e.g., "https://my-vault.vault.azure.net".
        #[arg(long, value_name = "URL", env = VAULT_ENV_NAME)]
        vault: Option<Url>,

        /// Show more details about each version.
        #[arg(long)]
        long: bool,
    },
}

impl Commands {
    pub async fn handle(&self, global_args: &crate::Args) -> Result<()> {
        match &self {
            Commands::Create { .. } => self.create().await,
            Commands::Edit { .. } => self.edit().await,
            Commands::EditPolicy { .. } => self.edit_policy(global_args).await,
            Commands::Get { .. } => self.get().await,
            Commands::GetPolicy { .. } => self.get_policy(global_args).await,
            Commands::List { .. } => self.list(global_args).await,
            Commands::ListVersions { .. } => self.list_versions(global_args).await,
        }
    }

    #[tracing::instrument(level = Level::INFO, skip(self), fields(vault, name), err)]
    async fn create(&self) -> Result<()> {
        let Commands::Create {
            name,
            vault,
            issuer,
            subject,
            validity,
            r#type,
            size,
            curve,
            exportable,
            reuse_key,
            key_usage,
            enhanced_key_usage,
            attributes:
                AttributeArgs {
                    enabled,
                    expires,
                    not_before,
                },
            tags,
        } = self
        else {
            panic!("invalid command");
        };

        let current = Span::current();
        current.record("vault", vault.as_str());
        current.record("name", name);

        let client = CertificateClient::new(vault.as_str(), credential(), None)?;

        let certificate_attributes = CertificateAttributes {
            enabled: *enabled,
            expires: *expires,
            not_before: *not_before,
            ..Default::default()
        };
        let params = CreateCertificateParameters {
            certificate_policy: Some(CertificatePolicy {
                key_properties: Some(KeyProperties {
                    key_type: Some(r#type.into()),
                    key_size: size.map(|value| *value),
                    curve: curve.map(Into::into),
                    exportable: Some(*exportable),
                    reuse_key: Some(*reuse_key),
                }),
                issuer_parameters: Some(IssuerParameters {
                    name: Some(issuer.clone()),
                    ..Default::default()
                }),
                x509_certificate_properties: Some(X509CertificateProperties {
                    key_usage: map_vec(Some(key_usage), Into::into),
                    enhanced_key_usage: map_vec(Some(enhanced_key_usage), Clone::clone),
                    subject: Some(subject.clone()),
                    validity_in_months: Some(*validity as i32),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            tags: map_tags(tags),
            certificate_attributes: certificate_attributes.default_or(),
            ..Default::default()
        };

        let spinner = ProgressBar::new_spinner().with_message("Creating certificate...");
        spinner.enable_steady_tick(Duration::from_millis(100));
        let status = client
            .begin_create_certificate(name, params.try_into()?, None)?
            .wait()
            .await?
            .into_body()?;
        spinner.finish_and_clear();

        if !matches!(status.status, Some(status) if status == "completed") {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Certificate creation failed: {}",
                    status.status_details.unwrap_or_default()
                ),
            ));
        }
        let Some(target) = status.target else {
            return Err(Error::new(
                ErrorKind::Other,
                "Certificate target not available",
            ));
        };
        let ResourceId { name, version, .. } = target.parse()?;
        let certificate = client
            .get_certificate(
                &name,
                Some(CertificateClientGetCertificateOptions {
                    certificate_version: version,
                    ..Default::default()
                }),
            )
            .await?
            .into_body()?;

        show(&certificate)
    }

    #[tracing::instrument(level = Level::INFO, skip(self), fields(vault, name, version), err)]
    async fn edit(&self) -> Result<()> {
        let Commands::Edit {
            id,
            vault,
            name,
            attributes:
                AttributeArgs {
                    enabled,
                    expires,
                    not_before,
                },
            tags,
        } = self
        else {
            panic!("invalid command");
        };

        let (vault, name, version) = super::select(id.as_ref(), vault.as_ref(), name.as_ref())?;
        let current = Span::current();
        current.record("vault", &*vault);
        current.record("name", &*name);
        current.record("version", version.as_deref());

        let client = CertificateClient::new(&vault, credential(), None)?;

        let certificate_attributes = CertificateAttributes {
            enabled: *enabled,
            expires: *expires,
            not_before: *not_before,
            ..Default::default()
        };
        let params = UpdateCertificatePropertiesParameters {
            tags: map_tags(tags),
            certificate_attributes: certificate_attributes.default_or(),
            ..Default::default()
        };

        let certificate = client
            .update_certificate_properties(
                &name,
                params.try_into()?,
                Some(CertificateClientUpdateCertificatePropertiesOptions {
                    certificate_version: version.map(Into::into),
                    ..Default::default()
                }),
            )
            .await?
            .into_body()?;

        show(&certificate)
    }

    #[tracing::instrument(level = Level::INFO, skip(self), fields(vault, name, version), err)]
    async fn edit_policy(&self, global_args: &crate::Args) -> Result<()> {
        let Commands::EditPolicy {
            id,
            vault,
            name,
            issuer,
            subject,
            validity,
            r#type,
            size,
            curve,
            exportable,
            reuse_key,
            key_usage,
            enhanced_key_usage,
        } = self
        else {
            panic!("invalid command");
        };

        let (vault, name, version) = super::select(id.as_ref(), vault.as_ref(), name.as_ref())?;
        let current = Span::current();
        current.record("vault", &*vault);
        current.record("name", &*name);
        current.record("version", version.as_deref());

        let client = CertificateClient::new(&vault, credential(), None)?;

        let key_properties = KeyProperties {
            key_type: r#type.map(Into::into),
            key_size: size.map(|value| *value),
            curve: curve.map(Into::into),
            exportable: exportable.map(Into::into),
            reuse_key: reuse_key.map(Into::into),
        };
        let issuer_properties = IssuerParameters {
            name: issuer.clone(),
            ..Default::default()
        };
        let x509_certificate_properties = X509CertificateProperties {
            key_usage: map_vec(key_usage.as_deref(), Into::into),
            enhanced_key_usage: map_vec(enhanced_key_usage.as_deref(), Clone::clone),
            subject: subject.clone(),
            validity_in_months: validity.map(|v| v as i32),
            ..Default::default()
        };
        let policy = CertificatePolicy {
            key_properties: key_properties.default_or(),
            issuer_parameters: issuer_properties.default_or(),
            x509_certificate_properties: x509_certificate_properties.default_or(),
            ..Default::default()
        };
        let params = UpdateCertificatePropertiesParameters {
            certificate_policy: policy.default_or(),
            ..Default::default()
        };

        let certificate = client
            .update_certificate_properties(
                &name,
                params.try_into()?,
                Some(CertificateClientUpdateCertificatePropertiesOptions {
                    certificate_version: version.map(Into::into),
                    ..Default::default()
                }),
            )
            .await?
            .into_body()?;

        if let Some(ref policy) = certificate.policy {
            json::print(policy, global_args.color())?;
        }

        Ok(())
    }

    #[tracing::instrument(level = Level::INFO, skip(self), fields(vault, name, version), err)]
    async fn get(&self) -> Result<()> {
        let Commands::Get { id, name, vault } = self else {
            panic!("invalid command");
        };

        let (vault, name, version) = super::select(id.as_ref(), vault.as_ref(), name.as_ref())?;
        let current = Span::current();
        current.record("vault", &*vault);
        current.record("name", &*name);
        current.record("version", version.as_deref());

        let client = CertificateClient::new(&vault, credential(), None)?;
        let certificate = client
            .get_certificate(
                &name,
                Some(CertificateClientGetCertificateOptions {
                    certificate_version: version.map(Into::into),
                    ..Default::default()
                }),
            )
            .await?
            .into_body()?;

        show(&certificate)
    }

    #[tracing::instrument(level = Level::INFO, skip(self), fields(vault, name), err)]
    async fn get_policy(&self, global_args: &crate::Args) -> std::result::Result<(), Error> {
        let Commands::GetPolicy { id, name, vault } = self else {
            panic!("Invalid command");
        };

        let (vault, name, ..) = super::select(id.as_ref(), vault.as_ref(), name.as_ref())?;
        let current = Span::current();
        current.record("vault", &*vault);
        current.record("name", &*name);

        let client = CertificateClient::new(&vault, credential(), None)?;
        let policy = client
            .get_certificate_policy(&name, None)
            .await?
            .into_body()?;

        json::print(&policy, global_args.color())
    }

    #[tracing::instrument(level = Level::INFO, skip(self), fields(vault), err)]
    async fn list(&self, global_args: &crate::Args) -> Result<()> {
        let Commands::List { vault, long } = self else {
            panic!("invalid command");
        };

        Span::current().record("vault", vault.as_str());

        let client = CertificateClient::new(vault.as_str(), credential(), None)?;
        let mut certificates: Vec<CertificateProperties> = client
            .list_certificate_properties(None)?
            .try_collect()
            .await?;
        certificates.sort_by(|a, b| a.id.cmp(&b.id));

        let mut table = Table::new();
        table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);

        let mut titles = Row::new(vec![
            Cell::new("NAME").with_style(Attr::Dim),
            Cell::new("ID").with_style(Attr::Dim),
        ]);
        if *long {
            titles.add_cell(Cell::new("CREATED").with_style(Attr::Dim));
        }
        titles.add_cell(Cell::new("EDITED").with_style(Attr::Dim));
        table.set_titles(titles);

        let now = OffsetDateTime::now_utc();
        let formatter = Formatter::new();
        let name_attr = Attr::ForegroundColor(color::GREEN);

        for certificate in &certificates {
            let resource: ResourceId = certificate.resource_id()?;
            let source_id = resource.source_id;

            let mut row = Row::new(vec![
                Cell::new(resource.name.as_str()).with_style(name_attr),
                Cell::new(source_id.as_str()),
            ]);
            if *long {
                let created = elapsed(
                    &formatter,
                    now,
                    certificate
                        .attributes
                        .as_ref()
                        .and_then(|attr| attr.created),
                );
                row.add_cell(Cell::new(created.as_str()));
            }
            let edited = elapsed(
                &formatter,
                now,
                certificate
                    .attributes
                    .as_ref()
                    .and_then(|attr| attr.updated),
            );
            row.add_cell(Cell::new(edited.as_str()));

            table.add_row(row);
        }

        // cspell:ignore printstd
        table.print_color_conditionally(global_args.color())?;

        Ok(())
    }

    #[tracing::instrument(level = Level::INFO, skip(self), fields(vault, name, version), err)]
    async fn list_versions(&self, global_args: &crate::Args) -> Result<()> {
        let Commands::ListVersions {
            id,
            name,
            vault,
            long,
        } = self
        else {
            panic!("invalid command");
        };

        let (vault, name, version) = super::select(id.as_ref(), vault.as_ref(), name.as_ref())?;
        let current = Span::current();
        current.record("vault", &*vault);
        current.record("name", &*name);
        current.record("version", version.as_deref());

        let client = CertificateClient::new(&vault, credential(), None)?;
        let mut certificates: Vec<CertificateProperties> = client
            .list_certificate_properties_versions(&name, None)?
            .try_collect()
            .await?;
        certificates.sort_by(|a, b| {
            let a = a.attributes.as_ref().and_then(|x| x.updated);
            let b = b.attributes.as_ref().and_then(|x| x.updated);
            a.cmp(&b).reverse()
        });

        let mut table = Table::new();
        table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);

        let mut titles = Row::new(vec![Cell::new("ID").with_style(Attr::Dim)]);
        if *long {
            titles.add_cell(Cell::new("CREATED").with_style(Attr::Dim));
        }
        titles.add_cell(Cell::new("EDITED").with_style(Attr::Dim));
        table.set_titles(titles);

        let now = OffsetDateTime::now_utc();
        let formatter = Formatter::new();
        let id_attr = Attr::ForegroundColor(color::GREEN);

        for certificate in &certificates {
            let resource: ResourceId = certificate.resource_id()?;
            let source_id = resource.source_id;

            let mut row = Row::new(vec![Cell::new(source_id.as_str()).with_style(id_attr)]);
            if *long {
                let created = elapsed(
                    &formatter,
                    now,
                    certificate
                        .attributes
                        .as_ref()
                        .and_then(|attr| attr.created),
                );
                row.add_cell(Cell::new(created.as_str()));
            }
            let edited = elapsed(
                &formatter,
                now,
                certificate
                    .attributes
                    .as_ref()
                    .and_then(|attr| attr.updated),
            );
            row.add_cell(Cell::new(edited.as_str()));

            table.add_row(row);
        }

        // cspell:ignore printstd
        table.print_color_conditionally(global_args.color())?;

        Ok(())
    }
}

fn show(certificate: &Certificate) -> Result<()> {
    let resource = certificate.resource_id()?;

    let now = OffsetDateTime::now_utc();
    let formatter = Formatter::new();

    println!("ID: {}", &resource.source_id);
    println!("Name: {}", &resource.name);
    println!("Version: {}", resource.version.unwrap_or_default());
    println!(
        "Thumbprint: {}",
        certificate
            .x509_thumbprint
            .as_ref()
            .map(|v| format!("{:X}", Bytes::copy_from_slice(v)))
            .unwrap_or_default()
    );
    let x509_properties = certificate
        .policy
        .as_ref()
        .and_then(|v| v.x509_certificate_properties.as_ref());
    println!(
        "Subject: {}",
        x509_properties
            .and_then(|v| v.subject.as_deref())
            .unwrap_or_default()
    );
    let key_usage = x509_properties
        .and_then(|v| v.key_usage.as_ref())
        .map(|v| {
            let mut c: Vec<String> = v
                .iter()
                .map(Into::<KeyUsageType>::into)
                .map(|v| v.to_string())
                .collect();
            c.sort();
            c
        })
        .unwrap_or_default();
    println!("Key usage:");
    for v in &key_usage {
        println!("  {v}")
    }
    println!(
        "Enabled: {}",
        certificate
            .attributes
            .as_ref()
            .and_then(|attr| attr.enabled)
            .unwrap_or_default()
    );
    println!(
        "Created: {}",
        elapsed(
            &formatter,
            now,
            certificate
                .attributes
                .as_ref()
                .and_then(|attr| attr.created)
        )
    );
    println!(
        "Edited: {}",
        elapsed(
            &formatter,
            now,
            certificate
                .attributes
                .as_ref()
                .and_then(|attr| attr.updated)
        )
    );
    println!(
        "Not before: {}",
        elapsed(
            &formatter,
            now,
            certificate
                .attributes
                .as_ref()
                .and_then(|attr| attr.not_before)
        )
    );
    println!(
        "Expires: {}",
        elapsed(
            &formatter,
            now,
            certificate
                .attributes
                .as_ref()
                .and_then(|attr| attr.expires)
        )
    );
    println!("Tags:");
    if let Some(tags) = &certificate.tags {
        for (k, v) in tags {
            println!("  {k}: {v}");
        }
    }

    Ok(())
}

impl From<KeyType> for azure_security_keyvault_certificates::models::KeyType {
    fn from(value: KeyType) -> Self {
        match value {
            KeyType::Ec => Self::Ec,
            KeyType::EcHsm => Self::EcHsm,
            KeyType::Rsa => Self::Rsa,
            KeyType::RsaHsm => Self::RsaHsm,
        }
    }
}

impl From<&KeyType> for azure_security_keyvault_certificates::models::KeyType {
    fn from(value: &KeyType) -> Self {
        (*value).into()
    }
}

impl From<CurveName> for azure_security_keyvault_certificates::models::CurveName {
    fn from(value: CurveName) -> Self {
        match value {
            CurveName::P256 => Self::P256,
            CurveName::P384 => Self::P384,
            CurveName::P521 => Self::P521,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ValueEnum)]
pub enum KeyUsageType {
    /// The certificate may be used to sign CRLs.
    CRLSign,
    /// The certificate may be used to encipher user data.
    DataEncipherment,
    /// The certificate may be used only for decryption when used with key agreement.
    DecipherOnly,
    /// The certificate may be used for digital signatures.
    DigitalSignature,
    /// The certificate may be used only for encryption when used with key agreement.
    EncipherOnly,
    /// The certificate may be used for key agreement.
    KeyAgreement,
    /// The certificate may be used to sign certificates.
    KeyCertSign,
    /// The certificate may be used to encipher private or secret keys.
    KeyEncipherment,
    /// The certificate may be used for non-repudiation.
    NonRepudiation,
    /// An unknown value returned by the service.
    #[value(skip)]
    UnknownValue(String),
}

impl fmt::Display for KeyUsageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = self.to_possible_value();
        f.write_str(value.as_ref().map_or_else(|| "(unknown)", |v| v.get_name()))
    }
}

impl From<&KeyUsageType> for azure_security_keyvault_certificates::models::KeyUsageType {
    fn from(value: &KeyUsageType) -> Self {
        match value {
            KeyUsageType::CRLSign => Self::CRlSign,
            KeyUsageType::DataEncipherment => Self::DataEncipherment,
            KeyUsageType::DecipherOnly => Self::DecipherOnly,
            KeyUsageType::DigitalSignature => Self::DigitalSignature,
            KeyUsageType::EncipherOnly => Self::EncipherOnly,
            KeyUsageType::KeyAgreement => Self::KeyAgreement,
            KeyUsageType::KeyCertSign => Self::KeyCertSign,
            KeyUsageType::KeyEncipherment => Self::KeyEncipherment,
            KeyUsageType::NonRepudiation => Self::NonRepudiation,
            KeyUsageType::UnknownValue(s) => Self::UnknownValue(s.clone()),
        }
    }
}

impl From<&azure_security_keyvault_certificates::models::KeyUsageType> for KeyUsageType {
    fn from(value: &azure_security_keyvault_certificates::models::KeyUsageType) -> Self {
        match value {
            azure_security_keyvault_certificates::models::KeyUsageType::CRlSign => Self::CRLSign,
            azure_security_keyvault_certificates::models::KeyUsageType::DataEncipherment => {
                Self::DataEncipherment
            }
            azure_security_keyvault_certificates::models::KeyUsageType::DecipherOnly => {
                Self::DecipherOnly
            }
            azure_security_keyvault_certificates::models::KeyUsageType::DigitalSignature => {
                Self::DigitalSignature
            }
            azure_security_keyvault_certificates::models::KeyUsageType::EncipherOnly => {
                Self::EncipherOnly
            }
            azure_security_keyvault_certificates::models::KeyUsageType::KeyAgreement => {
                Self::KeyAgreement
            }
            azure_security_keyvault_certificates::models::KeyUsageType::KeyCertSign => {
                Self::KeyCertSign
            }
            azure_security_keyvault_certificates::models::KeyUsageType::KeyEncipherment => {
                Self::KeyEncipherment
            }
            azure_security_keyvault_certificates::models::KeyUsageType::NonRepudiation => {
                Self::NonRepudiation
            }
            azure_security_keyvault_certificates::models::KeyUsageType::UnknownValue(s) => {
                Self::UnknownValue(s.clone())
            }
            _ => Self::UnknownValue("(unknown)".into()),
        }
    }
}

impl IsDefault for KeyProperties {
    fn is_default(&self) -> bool {
        self.curve.is_none()
            && self.exportable.is_none()
            && self.key_size.is_none()
            && self.key_type.is_none()
            && self.reuse_key.is_none()
    }
}

impl IsDefault for IssuerParameters {
    fn is_default(&self) -> bool {
        self.certificate_transparency.is_none()
            && self.certificate_type.is_none()
            && self.name.is_none()
    }
}

impl IsDefault for X509CertificateProperties {
    fn is_default(&self) -> bool {
        self.enhanced_key_usage.is_none()
            && self.key_usage.is_none()
            && self.subject.is_none()
            && self.subject_alternative_names.is_none()
            && self.validity_in_months.is_none()
    }
}

impl IsDefault for CertificatePolicy {
    fn is_default(&self) -> bool {
        self.attributes.is_none()
            && self.id.is_none()
            && self.issuer_parameters.is_none()
            && self.key_properties.is_none()
            && self.lifetime_actions.is_none()
            && self.secret_properties.is_none()
            && self.x509_certificate_properties.is_none()
    }
}

impl IsDefault for CertificateAttributes {
    fn is_default(&self) -> bool {
        self.enabled.is_none() && self.expires.is_none() && self.not_before.is_none()
    }
}
