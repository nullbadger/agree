use {
    crate::{
        error::Error,
        scheme::{
            ShareCount,
            Threshold,
        },
        secret::SecretBytes,
    },
    anyhow::{
        Context,
        Result,
    },
    base64::{
        engine::general_purpose::STANDARD,
        Engine,
    },
    serde::{
        Deserialize,
        Deserializer,
        Serialize,
        Serializer,
    },
    std::{
        fmt,
        path::{
            Path,
            PathBuf,
        },
    },
    uuid::Uuid,
    zeroize::{
        Zeroize,
        ZeroizeOnDrop,
    },
};

/// HMAC nonce stored beside each share. The key itself stays inside the Shamir
/// payload.
pub(crate) const AUTH_NONCE_LEN: usize = 32;
/// HMAC-SHA512 tag length.
pub(crate) const AUTH_TAG_LEN: usize = 64;

/// Archive format version. Only `major.minor` is persisted; patch releases stay
/// compatible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ArchiveVersion {
    major: u64,
    minor: u64,
}

impl ArchiveVersion {
    pub(crate) fn current() -> Self {
        Self::from_package(env!("CARGO_PKG_VERSION")).expect("CARGO_PKG_VERSION is major.minor.patch")
    }

    pub(crate) fn parse(value: &str) -> Result<Self, Error> {
        if value.len() > 32 {
            return Err(Error::InvalidVersion);
        }
        let Some((major, minor)) = value.split_once('.') else {
            return Err(Error::InvalidVersion);
        };
        if minor.contains('.') {
            return Err(Error::InvalidVersion);
        }
        let parsed = Self::from_parts(major, minor)?;
        if parsed.to_string() != value {
            return Err(Error::InvalidVersion);
        }
        Ok(parsed)
    }

    fn from_package(version: &str) -> Result<Self, Error> {
        let bare = version.split('-').next().unwrap_or(version);
        let mut parts = bare.split('.');
        let major = parts.next().ok_or(Error::InvalidVersion)?;
        let minor = parts.next().ok_or(Error::InvalidVersion)?;
        Self::from_parts(major, minor)
    }

    fn from_parts(major: &str, minor: &str) -> Result<Self, Error> {
        if major.is_empty()
            || minor.is_empty()
            || !major.bytes().all(|byte| byte.is_ascii_digit())
            || !minor.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(Error::InvalidVersion);
        }
        Ok(Self {
            major: major.parse().map_err(|_| Error::InvalidVersion)?,
            minor: minor.parse().map_err(|_| Error::InvalidVersion)?,
        })
    }
}

impl fmt::Display for ArchiveVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl Serialize for ArchiveVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ArchiveVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// Identifier of one share file. Distinct from [`GroupId`] so the two cannot be
/// swapped.
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub(crate) struct ShareUid(Uuid);

impl ShareUid {
    pub(crate) fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl fmt::Display for ShareUid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.hyphenated())
    }
}

impl fmt::Debug for ShareUid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Serialize for ShareUid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ShareUid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        parse_uuid(deserializer).map(Self)
    }
}

/// Identifier shared by every share produced by one split.
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub(crate) struct GroupId(Uuid);

impl GroupId {
    pub(crate) fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl fmt::Display for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.hyphenated())
    }
}

impl fmt::Debug for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Serialize for GroupId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for GroupId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        parse_uuid(deserializer).map(Self)
    }
}

fn parse_uuid<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Uuid, D::Error> {
    let value = String::deserialize(deserializer)?;
    if value.len() > 64 {
        return Err(serde::de::Error::custom(Error::InvalidIdentifier));
    }
    Uuid::parse_str(&value).map_err(|_| serde::de::Error::custom(Error::InvalidIdentifier))
}

/// Public authentication tag. The HMAC key is not stored here; it is split with
/// the secret.
#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub(crate) struct AuthTag {
    nonce: [u8; AUTH_NONCE_LEN],
    tag: [u8; AUTH_TAG_LEN],
}

impl AuthTag {
    pub(crate) fn new(nonce: [u8; AUTH_NONCE_LEN], tag: [u8; AUTH_TAG_LEN]) -> Self {
        Self { nonce, tag }
    }

    pub(crate) fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    pub(crate) fn tag(&self) -> &[u8] {
        &self.tag
    }
}

impl fmt::Debug for AuthTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthTag(<redacted>)")
    }
}

impl Serialize for AuthTag {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        RawAuthTag {
            nonce: STANDARD.encode(self.nonce),
            tag: STANDARD.encode(self.tag),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AuthTag {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawAuthTag::deserialize(deserializer)?;
        let nonce = decode_array::<AUTH_NONCE_LEN>(&raw.nonce, "auth nonce").map_err(serde::de::Error::custom)?;
        let tag = decode_array::<AUTH_TAG_LEN>(&raw.tag, "auth tag").map_err(serde::de::Error::custom)?;
        Ok(Self::new(nonce, tag))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct RawAuthTag {
    nonce: String,
    tag: String,
}

fn decode_array<const N: usize>(value: &str, what: &str) -> Result<[u8; N], Error> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| Error::InvalidArchive(format!("invalid {what} encoding")))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| Error::InvalidArchive(format!("{what} length is {}, expected {N}", bytes.len())))
}

/// One share file read at the CLI boundary.
pub(crate) struct ShareFile {
    path: PathBuf,
    bytes: SecretBytes,
}

impl ShareFile {
    pub(crate) fn new(path: PathBuf, bytes: Vec<u8>) -> Self {
        Self {
            path,
            bytes: SecretBytes::new(bytes),
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl fmt::Debug for ShareFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareFile")
            .field("path", &self.path)
            .field("bytes", &self.bytes)
            .finish()
    }
}

/// On-disk archive. `data` is the decoded inner JSON, never the caller's secret
/// by itself.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct Archive {
    version: ArchiveVersion,
    uid: ShareUid,
    pid: GroupId,
    #[serde(with = "base64_secret")]
    data: SecretBytes,
}

impl Archive {
    pub(crate) fn create(version: ArchiveVersion, pid: GroupId, data: &ArchiveData) -> Result<Self> {
        Ok(Self {
            version,
            uid: ShareUid::new(),
            pid,
            data: encode_archive_data(data)?,
        })
    }

    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).context("Failed to parse share archive")
    }

    pub(crate) fn to_vec(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("Failed to serialize share archive")
    }

    pub(crate) fn version(&self) -> ArchiveVersion {
        self.version
    }

    pub(crate) fn uid(&self) -> ShareUid {
        self.uid
    }

    pub(crate) fn group_id(&self) -> GroupId {
        self.pid
    }

    pub(crate) fn archive_data(&self) -> Result<ArchiveData> {
        serde_json::from_slice(self.data.as_slice()).context("Failed to decode archive data")
    }

    pub(crate) fn set_data(&mut self, data: &ArchiveData) -> Result<()> {
        self.data = encode_archive_data(data)?;
        Ok(())
    }

    pub(crate) fn report(&self) -> Result<ShareReport> {
        let data = self.archive_data()?;
        Ok(ShareReport {
            version: self.version,
            uid: self.uid,
            pid: self.pid,
            encrypted: data.share.is_encrypted(),
            comment: data.info.comment().map(str::to_owned),
            secret: data.info.secret(),
        })
    }
}

fn encode_archive_data(data: &ArchiveData) -> Result<SecretBytes> {
    Ok(SecretBytes::new(
        serde_json::to_vec(data).context("Failed to serialize archive data")?,
    ))
}

/// Metadata that `info` is allowed to print. It cannot represent share bytes.
#[derive(Debug)]
pub(crate) struct ShareReport {
    version: ArchiveVersion,
    uid: ShareUid,
    pid: GroupId,
    encrypted: bool,
    comment: Option<String>,
    secret: Option<SecretInfo>,
}

impl fmt::Display for ShareReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Version:\t{}", self.version)?;
        writeln!(f, "UID:\t\t{}", self.uid)?;
        writeln!(f, "PID:\t\t{}", self.pid)?;
        writeln!(f, "Encryption:\t{}", if self.encrypted { "encrypted" } else { "plain" })?;
        writeln!(f, "Comment:\t{}", self.comment.as_deref().unwrap_or("(none)"))?;
        match self.secret {
            | Some(info) => {
                writeln!(
                    f,
                    "Threshold:\t{} of {}",
                    info.threshold().as_usize(),
                    info.num_shares().get()
                )?;
            },
            | None => writeln!(f, "Threshold:\tomitted")?,
        }
        write!(f, "Payload:\t<redacted>")
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct ArchiveData {
    share: Share,
    info: ShareInfo,
}

impl ArchiveData {
    pub(crate) fn new(share: Share, info: ShareInfo) -> Self {
        Self { share, info }
    }

    pub(crate) fn into_parts(self) -> (Share, ShareInfo) {
        (self.share, self.info)
    }

    #[cfg(test)]
    pub(crate) fn redacted_json(&self) -> serde_json::Value {
        let kind = if self.share.is_encrypted() {
            "encrypted"
        } else {
            "plain"
        };
        serde_json::json!({
            "share": {
                kind: {
                    "data": "<redacted>",
                    "auth": {
                        "nonce": "<redacted>",
                        "tag": "<redacted>",
                    },
                },
            },
            "info": self.info,
        })
    }
}

impl fmt::Debug for ArchiveData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArchiveData")
            .field("share", &self.share)
            .field("info", &self.info)
            .finish()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct ShareInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secret: Option<SecretInfo>,
}

impl ShareInfo {
    pub(crate) fn new(comment: Option<String>, secret: Option<SecretInfo>) -> Self {
        Self { comment, secret }
    }

    pub(crate) fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    pub(crate) fn secret(&self) -> Option<SecretInfo> {
        self.secret
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "RawSecretInfo", into = "RawSecretInfo")]
pub(crate) struct SecretInfo {
    num_shares: ShareCount,
    threshold: Threshold,
}

impl SecretInfo {
    pub(crate) fn new(num_shares: ShareCount, threshold: Threshold) -> Result<Self> {
        if threshold.as_usize() > num_shares.get() {
            anyhow::bail!(
                "threshold {} exceeds share count {}",
                threshold.as_usize(),
                num_shares.get()
            );
        }
        Ok(Self { num_shares, threshold })
    }

    pub(crate) fn num_shares(self) -> ShareCount {
        self.num_shares
    }

    pub(crate) fn threshold(self) -> Threshold {
        self.threshold
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct RawSecretInfo {
    num_shares: u64,
    threshold: u64,
}

impl From<SecretInfo> for RawSecretInfo {
    fn from(info: SecretInfo) -> Self {
        Self {
            num_shares: u64::try_from(info.num_shares.get()).expect("share count fits in u64"),
            threshold: u64::from(info.threshold.get()),
        }
    }
}

impl TryFrom<RawSecretInfo> for SecretInfo {
    type Error = anyhow::Error;

    fn try_from(raw: RawSecretInfo) -> Result<Self, Self::Error> {
        let num_shares = ShareCount::new(usize::try_from(raw.num_shares).context("share count does not fit")?)?;
        let threshold = Threshold::new(usize::try_from(raw.threshold).context("threshold does not fit")?)?;
        Self::new(num_shares, threshold).context("invalid secret info")
    }
}

/// Share payload after base64 decoding. Plain and encrypted are different
/// states, not a flag.
pub(crate) enum Share {
    Plain { data: SecretBytes, auth: AuthTag },
    Encrypted { data: SecretBytes, auth: AuthTag },
}

pub(crate) enum ShareBody {
    Plain(SecretBytes),
    Encrypted(SecretBytes),
}

impl Share {
    pub(crate) fn plain(data: SecretBytes, auth: AuthTag) -> Self {
        Self::Plain { data, auth }
    }

    pub(crate) fn encrypted(data: SecretBytes, auth: AuthTag) -> Self {
        Self::Encrypted { data, auth }
    }

    pub(crate) fn is_encrypted(&self) -> bool {
        matches!(self, Self::Encrypted { .. })
    }

    pub(crate) fn into_parts(self) -> (ShareBody, AuthTag) {
        match self {
            | Self::Plain { data, auth } => (ShareBody::Plain(data), auth),
            | Self::Encrypted { data, auth } => (ShareBody::Encrypted(data), auth),
        }
    }
}

impl fmt::Debug for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | Self::Plain { .. } => f.write_str("Share::Plain(<redacted>)"),
            | Self::Encrypted { .. } => f.write_str("Share::Encrypted(<redacted>)"),
        }
    }
}

impl Serialize for Share {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let (kind, data, auth) = match self {
            | Self::Plain { data, auth } => ("plain", data, auth),
            | Self::Encrypted { data, auth } => ("encrypted", data, auth),
        };
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry(kind, &ShareBodySer { data, auth })?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for Share {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawShare::deserialize(deserializer)?;
        match (raw.plain, raw.encrypted) {
            | (Some(body), None) => {
                let (data, auth) = body.into_parts().map_err(serde::de::Error::custom)?;
                Ok(Self::plain(data, auth))
            },
            | (None, Some(body)) => {
                let (data, auth) = body.into_parts().map_err(serde::de::Error::custom)?;
                Ok(Self::encrypted(data, auth))
            },
            | (Some(_), Some(_)) => Err(serde::de::Error::custom("share cannot be both plain and encrypted")),
            | (None, None) => Err(serde::de::Error::custom("share requires plain or encrypted")),
        }
    }
}

struct ShareBodySer<'a> {
    data: &'a SecretBytes,
    auth: &'a AuthTag,
}

impl Serialize for ShareBodySer<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut encoded = STANDARD.encode(self.data.as_slice());
        let mut state = serializer.serialize_struct("ShareBody", 2)?;
        let data_result = state.serialize_field("data", &encoded);
        encoded.zeroize();
        data_result?;
        state.serialize_field("auth", self.auth)?;
        state.end()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct RawShare {
    #[serde(default)]
    plain: Option<RawBody>,
    #[serde(default)]
    encrypted: Option<RawBody>,
}

struct RawBody {
    data: String,
    auth: AuthTag,
}

impl RawBody {
    fn into_parts(mut self) -> Result<(SecretBytes, AuthTag), Error> {
        let mut encoded = std::mem::take(&mut self.data);
        let auth = std::mem::replace(&mut self.auth, AuthTag::new([0; AUTH_NONCE_LEN], [0; AUTH_TAG_LEN]));
        let decoded = decode_secret(&encoded);
        encoded.zeroize();
        Ok((decoded?, auth))
    }
}

impl Drop for RawBody {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl<'de> Deserialize<'de> for RawBody {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case", deny_unknown_fields)]
        struct Wire {
            data: String,
            auth: AuthTag,
        }
        let wire = Wire::deserialize(deserializer)?;
        Ok(Self {
            data: wire.data,
            auth: wire.auth,
        })
    }
}

fn decode_secret(text: &str) -> Result<SecretBytes, Error> {
    STANDARD
        .decode(text)
        .map(SecretBytes::new)
        .map_err(|_| Error::InvalidArchive("invalid base64".to_owned()))
}

mod base64_secret {
    use {
        super::SecretBytes,
        crate::error::Error,
        base64::{
            engine::general_purpose::STANDARD,
            Engine,
        },
        serde::{
            Deserialize,
            Deserializer,
            Serializer,
        },
        zeroize::Zeroize,
    };

    pub(super) fn serialize<S: Serializer>(bytes: &SecretBytes, serializer: S) -> Result<S::Ok, S::Error> {
        let mut encoded = STANDARD.encode(bytes.as_slice());
        let result = serializer.serialize_str(&encoded);
        encoded.zeroize();
        result
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<SecretBytes, D::Error> {
        let mut text = String::deserialize(deserializer)?;
        let decoded = STANDARD
            .decode(&text)
            .map(SecretBytes::new)
            .map_err(|_| serde::de::Error::custom(Error::InvalidArchive("invalid base64".to_owned())));
        text.zeroize();
        decoded
    }
}

#[cfg(test)]
mod tests {
    use {
        super::{
            Archive,
            ArchiveData,
            ArchiveVersion,
            AuthTag,
            SecretInfo,
            Share,
            ShareInfo,
        },
        crate::{
            scheme::{
                ShareCount,
                Threshold,
            },
            secret::SecretBytes,
        },
        base64::{
            engine::general_purpose::STANDARD,
            Engine,
        },
    };

    fn sample_auth() -> AuthTag {
        AuthTag::new([7; 32], [9; 64])
    }

    #[test]
    fn package_version_drops_the_patch() {
        assert_eq!(ArchiveVersion::current().to_string(), "0.0");
        assert!(ArchiveVersion::parse("0.0.1").is_err());
        assert!(ArchiveVersion::parse("00.0").is_err());
        assert_eq!(ArchiveVersion::parse("0.0").unwrap().to_string(), "0.0");
    }

    #[test]
    fn empty_info_and_share_roundtrip() {
        let data = ArchiveData::new(
            Share::plain(SecretBytes::new(b"share-bytes".to_vec()), sample_auth()),
            ShareInfo::new(None, None),
        );
        let archive = Archive::create(ArchiveVersion::parse("0.0").unwrap(), super::GroupId::new(), &data).unwrap();
        let bytes = archive.to_vec().unwrap();
        let parsed = Archive::parse(&bytes).unwrap();
        let (share, info) = parsed.archive_data().unwrap().into_parts();
        assert!(info.secret().is_none());
        assert!(!share.is_encrypted());
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(value.get("version").is_some());
        assert!(value.get("uid").is_some());
        assert!(value.get("pid").is_some());
        assert!(value.get("data").is_some());
    }

    #[test]
    fn rejects_legacy_checksum_and_bad_auth_length() {
        let legacy = r#"{"share":{"plain":{"data":"","checksum":"embedded_v1"}},"info":{}}"#;
        assert!(serde_json::from_str::<ArchiveData>(legacy).is_err());

        let nonce = STANDARD.encode([1u8; 32]);
        let short_tag = STANDARD.encode([2u8; 8]);
        let bad = format!(
            r#"{{"share":{{"plain":{{"data":"YQ==","auth":{{"nonce":"{nonce}","tag":"{short_tag}"}}}}}},"info":{{}}}}"#
        );
        assert!(serde_json::from_str::<ArchiveData>(&bad).is_err());
    }

    #[test]
    fn secret_info_rejects_threshold_above_share_count() {
        let err = SecretInfo::new(ShareCount::new(1).unwrap(), Threshold::new(2).unwrap());
        assert!(err.is_err());
    }
}
