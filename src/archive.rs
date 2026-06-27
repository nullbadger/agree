use {
    crate::error::Error,
    anyhow::{
        Context,
        Result,
    },
    base64::{
        engine::general_purpose::STANDARD,
        Engine,
    },
    serde_json::json,
    std::fmt,
};

#[derive(Clone, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct Base64String(String);

impl Base64String {
    pub(crate) fn new<T: AsRef<[u8]>>(value: T) -> Self {
        Self(STANDARD.encode(value))
    }

    pub(crate) fn decode(&self) -> Result<Vec<u8>> {
        STANDARD
            .decode(&self.0)
            .map_err(|_| Error::Decoding("base64".to_owned()).into())
    }
}

impl fmt::Debug for Base64String {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Base64String(<redacted>)")
    }
}

/// The archive that stores one share and its metadata.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct Archive {
    /// Archive format version.
    pub version: String,
    /// Unique share ID.
    pub uid: String,
    /// Process/group ID shared by archives generated together.
    pub pid: String,
    /// Base64-encoded [`ArchiveData`] JSON.
    pub data: Base64String,
}

impl Archive {
    pub(crate) fn decode_data(&self) -> Result<ArchiveData> {
        serde_json::from_slice::<ArchiveData>(&self.data.decode()?).context("Failed to decode archive data")
    }
}

/// The decoded archive data.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct ArchiveData {
    /// The actual share of the secret.
    pub share: Share,
    /// Share information.
    pub info: ShareInfo,
}

impl ArchiveData {
    pub(crate) fn redacted_json(&self) -> serde_json::Value {
        let auth = json!({
            "nonce": "<redacted>",
            "tag": "<redacted>",
        });

        let share = match &self.share {
            | Share::Plain { .. } => {
                json!({
                    "plain": {
                        "data": "<redacted>",
                        "auth": auth,
                    },
                })
            },
            | Share::Encrypted { .. } => {
                json!({
                    "encrypted": {
                        "data": "<redacted>",
                        "auth": auth,
                    },
                })
            },
        };

        json!({
            "share": share,
            "info": self.info,
        })
    }
}

/// HMAC-SHA512 tag keyed by bytes embedded inside the Shamir payload.
#[derive(Debug, Clone, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct AuthTag {
    pub nonce: Base64String,
    pub tag: Base64String,
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct ShareInfo {
    /// Some plain text comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Some information about the secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<SecretInfo>,
}

// Describing an individual share.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Share {
    Plain { data: Base64String, auth: AuthTag },
    Encrypted { data: Base64String, auth: AuthTag },
}

/// Describes the secret that has been sharded. Contains information about how
/// to restore.
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct SecretInfo {
    /// The amount of shares that were generated for the secret.
    pub num_shares: usize,
    /// The amount of shares that are needed for restoring the secret.
    pub threshold: usize,
}
