mod dense_date_format;

use std::collections::HashMap;

use chrono::NaiveDate;
use serde::Deserialize;

pub const URL: &str = "https://iextrading.com/api/1.0/hist";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub(crate) struct DumpMetadata {
    /// A URL to the compressed dump file
    pub link: String,

    #[serde(with = "dense_date_format")]
    /// The date of the dump
    pub date: NaiveDate,

    /// The feed protocol type. It must be either 'TOSP' or 'DEEP'
    pub feed: String,

    /// The feed protocol version. It must be either '1.5' or '1.6' for TOPS or '1.0' for DEEP.
    pub version: String,

    /// The transfer protocol. It must be 'IEXTP1'.
    pub protocol: String,

    /// The size of the compressed file in bytes
    pub size: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hist(pub(crate) HashMap<String, Vec<DumpMetadata>>);
