use {
    crate::{
        error::Error,
        paths::PathResolver,
        policy::ShellTrust,
        scheme::{
            ShareCount,
            Threshold,
        },
        secret::{
            Password,
            SecretBytes,
            MAX_PASSWORD_BYTES,
        },
    },
    anyhow::{
        Context,
        Result,
    },
    serde::Deserialize,
    std::{
        collections::{
            HashMap,
            HashSet,
        },
        fmt,
        io::{
            self,
            Read,
        },
        path::{
            Path,
            PathBuf,
        },
        process::{
            Command,
            Stdio,
        },
        thread,
    },
    zeroize::{
        Zeroize,
        ZeroizeOnDrop,
    },
};

/// Validated split plan. Invalid thresholds, paths, and passwords cannot be
/// represented.
pub(crate) struct Blueprint {
    threshold: Threshold,
    shares: Vec<BlueprintShare>,
}

impl Blueprint {
    pub(crate) fn from_hocon(bytes: &[u8], paths: &PathResolver) -> Result<Self> {
        let mut text = match String::from_utf8(bytes.to_vec()) {
            | Ok(text) => text,
            | Err(err) => {
                let mut raw = err.into_bytes();
                raw.zeroize();
                anyhow::bail!("Blueprint is not valid UTF-8");
            },
        };
        let result = parse_hocon(&text, paths);
        text.zeroize();
        result
    }

    pub(crate) fn try_new(threshold: usize, shares: Vec<ShareSpec>, paths: &PathResolver) -> Result<Self> {
        if shares.is_empty() {
            anyhow::bail!("Blueprint must generate at least one share");
        }
        if shares.len() > ShareCount::MAX {
            anyhow::bail!(
                "Blueprint generates too many shares: {} > {}",
                shares.len(),
                ShareCount::MAX
            );
        }
        if threshold == 0 {
            anyhow::bail!("Blueprint threshold must be greater than 0");
        }
        if threshold > shares.len() {
            anyhow::bail!(
                "Blueprint threshold {threshold} exceeds generated share count {}",
                shares.len()
            );
        }
        let threshold = Threshold::new(threshold).context("invalid blueprint threshold")?;
        let mut seen = HashSet::new();
        let mut validated = Vec::with_capacity(shares.len());
        for share in shares {
            if share.path.as_os_str().is_empty() {
                anyhow::bail!("Blueprint share path must not be empty");
            }
            let path = paths.resolve(&share.path)?;
            if path.file_name().is_none() {
                anyhow::bail!("Blueprint share path must name a file: {}", path.display());
            }
            if !seen.insert(path.clone()) {
                anyhow::bail!("Duplicate share output path: {}", path.display());
            }
            validated.push(BlueprintShare {
                path,
                encrypt: share.encrypt,
                comment: share.comment,
                include_info: share.include_info,
            });
        }
        Ok(Self {
            threshold,
            shares: validated,
        })
    }

    pub(crate) fn threshold(&self) -> Threshold {
        self.threshold
    }

    pub(crate) fn secret_info(&self) -> Result<crate::archive::SecretInfo> {
        crate::archive::SecretInfo::new(ShareCount::new(self.shares.len())?, self.threshold)
            .context("invalid blueprint metadata")
    }

    pub(crate) fn shares(&self) -> &[BlueprintShare] {
        &self.shares
    }

    pub(crate) fn paths(&self) -> impl Iterator<Item=&Path> {
        self.shares.iter().map(|share| share.path.as_path())
    }

    pub(crate) fn requires_shell(&self) -> bool {
        self.shares
            .iter()
            .any(|share| share.encrypt.as_ref().is_some_and(BlueprintShareEncryption::is_shell))
    }

    pub(crate) fn ensure_trust(&self, trust: ShellTrust) -> Result<()> {
        if self.requires_shell() && trust != ShellTrust::Trusted {
            return Err(Error::ShellNotTrusted.into());
        }
        Ok(())
    }

    /// Resolves every password before any share is split, so a provider failure
    /// cannot leave a partial secret in memory longer than the input
    /// itself.
    pub(crate) fn resolve_passwords(&self, trust: ShellTrust) -> Result<Vec<Option<Password>>> {
        self.ensure_trust(trust)?;
        self.shares
            .iter()
            .map(|share| share.encrypt.as_ref().map(|encrypt| encrypt.resolve(trust)).transpose())
            .collect()
    }
}

/// Unvalidated share request. [`Blueprint::try_new`] is what makes it real.
pub(crate) struct ShareSpec {
    pub(crate) path: PathBuf,
    pub(crate) encrypt: Option<BlueprintShareEncryption>,
    pub(crate) comment: Option<String>,
    pub(crate) include_info: bool,
}

pub(crate) struct BlueprintShare {
    path: PathBuf,
    encrypt: Option<BlueprintShareEncryption>,
    comment: Option<String>,
    include_info: bool,
}

impl BlueprintShare {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    pub(crate) fn include_info(&self) -> bool {
        self.include_info
    }
}

/// Password source for one share. The shell script is cleared on drop because
/// it may embed a secret.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) enum BlueprintShareEncryption {
    Plain(Password),
    Shell(String),
}

impl BlueprintShareEncryption {
    pub(crate) fn plain(password: Password) -> Self {
        Self::Plain(password)
    }

    #[cfg(test)]
    pub(crate) fn shell(script: String) -> Self {
        Self::Shell(script)
    }

    pub(crate) fn is_shell(&self) -> bool {
        matches!(self, Self::Shell(_))
    }

    pub(crate) fn resolve(&self, trust: ShellTrust) -> Result<Password> {
        match self {
            | Self::Plain(password) => Ok(password.clone()),
            | Self::Shell(script) => exec_shell(script, trust),
        }
    }
}

impl fmt::Debug for BlueprintShareEncryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | Self::Plain(_) => f.write_str("Plain(<redacted>)"),
            | Self::Shell(_) => f.write_str("Shell(<redacted>)"),
        }
    }
}

impl<'de> Deserialize<'de> for BlueprintShareEncryption {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: serde::Deserializer<'de> {
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case", deny_unknown_fields)]
        struct Input {
            plain: Option<String>,
            shell: Option<String>,
        }

        let input = Input::deserialize(deserializer)?;
        match (input.plain, input.shell) {
            | (Some(password), None) => {
                Password::new(password)
                    .map(Self::Plain)
                    .map_err(serde::de::Error::custom)
            },
            | (None, Some(script)) => {
                if script.is_empty() {
                    return Err(serde::de::Error::custom("shell password provider must not be empty"));
                }
                Ok(Self::Shell(script))
            },
            | (None, None) => Err(serde::de::Error::custom("encrypt requires plain or shell")),
            | (Some(mut password), Some(_)) => {
                password.zeroize();
                Err(serde::de::Error::custom("encrypt cannot contain both plain and shell"))
            },
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct RawBlueprint {
    threshold: usize,
    generate: Vec<RawShare>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct RawShare {
    path: PathBuf,
    #[serde(default)]
    encrypt: Option<BlueprintShareEncryption>,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default = "default_include_info")]
    info: bool,
}

fn default_include_info() -> bool {
    true
}

fn parse_hocon(text: &str, paths: &PathResolver) -> Result<Blueprint> {
    // Reject the directive before parse. `include` inside a path is one unquoted
    // token, not this.
    for token in hocon::tokenize(text).context("Failed to tokenize blueprint")? {
        if token.kind == hocon::TokenKind::Unquoted && token.value == "include" {
            anyhow::bail!("Blueprint include directives are not allowed");
        }
    }

    // Empty map: substitutions must not read the process environment.
    let raw = hocon::parse_with_env(text, &HashMap::new())
        .context("Failed to parse blueprint")?
        .deserialize::<RawBlueprint>()
        .context("Failed to deserialize blueprint")?;
    let shares = raw
        .generate
        .into_iter()
        .map(|share| {
            ShareSpec {
                path: share.path,
                encrypt: share.encrypt,
                comment: share.comment,
                include_info: share.info,
            }
        })
        .collect();
    Blueprint::try_new(raw.threshold, shares, paths)
}

fn exec_shell(script: &str, trust: ShellTrust) -> Result<Password> {
    if trust != ShellTrust::Trusted {
        return Err(Error::ShellNotTrusted.into());
    }

    let mut child = Command::new("sh")
        .arg("-c")
        .arg(script)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to execute password provider")?;
    let mut waited = false;
    let result = (|| -> Result<Password> {
        let stdout = child
            .stdout
            .take()
            .context("password provider stdout was unavailable")?;
        let stderr = child
            .stderr
            .take()
            .context("password provider stderr was unavailable")?;
        let stdout_limit = MAX_PASSWORD_BYTES.saturating_add(2);
        let stderr_limit = 4096;
        let stdout_thread = thread::spawn(move || read_capped(stdout, stdout_limit));
        let stderr_thread = thread::spawn(move || read_capped(stderr, stderr_limit));
        let status = child.wait();
        waited = status.is_ok();
        let stdout = join_reader(stdout_thread).map(SecretBytes::new);
        let stderr = join_reader(stderr_thread).map(SecretBytes::new);
        finish_provider(
            status.context("Failed to wait for password provider")?,
            stdout?,
            stderr?,
            stdout_limit,
            stderr_limit,
        )
    })();
    if !waited {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

fn join_reader(handle: thread::JoinHandle<io::Result<Vec<u8>>>) -> Result<Vec<u8>> {
    match handle.join() {
        | Ok(Ok(bytes)) => Ok(bytes),
        | Ok(Err(err)) => Err(err).context("Failed to read password provider output"),
        | Err(_) => anyhow::bail!("password provider reader failed"),
    }
}

fn finish_provider(
    status: std::process::ExitStatus,
    stdout: SecretBytes,
    stderr: SecretBytes,
    stdout_limit: usize,
    stderr_limit: usize,
) -> Result<Password> {
    if stdout.len() > stdout_limit || stderr.len() > stderr_limit {
        anyhow::bail!("password provider output exceeds {MAX_PASSWORD_BYTES} bytes");
    }
    if !status.success() {
        let message = String::from_utf8_lossy(stderr.as_slice()).trim().to_owned();
        anyhow::bail!("Password provider failed: {message}");
    }
    let text = std::str::from_utf8(stdout.as_slice()).context("Password provider output is not valid UTF-8")?;
    Password::new(text.trim_end_matches(['\n', '\r']).to_owned()).map_err(Into::into)
}

fn read_capped(mut reader: impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while buf.len() <= limit {
        let read = match reader.read(&mut chunk) {
            | Ok(0) => break,
            | Ok(read) => read,
            | Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            | Err(err) => return Err(err),
        };
        let room = limit.saturating_add(1).saturating_sub(buf.len());
        let take = read.min(room);
        buf.extend_from_slice(&chunk[..take]);
        if take < read || buf.len() > limit {
            break;
        }
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use {
        super::{
            Blueprint,
            BlueprintShareEncryption,
            ShareSpec,
        },
        crate::{
            paths::PathResolver,
            policy::ShellTrust,
        },
        std::path::PathBuf,
    };

    fn resolver() -> PathResolver {
        PathResolver::with_cwd(PathBuf::from("/tmp/agree"))
    }

    #[test]
    fn parses_hocon_and_defaults_info_to_included() {
        let blueprint = Blueprint::from_hocon(
            br#"
                threshold = 1
                generate = [
                  { path = "alice.share", encrypt = { plain = "password" } }
                ]
            "#,
            &resolver(),
        )
        .expect("blueprint parses");
        assert_eq!(blueprint.threshold().as_usize(), 1);
        assert!(blueprint.shares()[0].include_info());
        assert_eq!(blueprint.shares()[0].path(), PathBuf::from("/tmp/agree/alice.share"));
    }

    #[test]
    fn rejects_includes_but_allows_the_word_inside_a_path() {
        assert!(Blueprint::from_hocon(br#"include "other.conf""#, &resolver()).is_err());
        let blueprint = Blueprint::from_hocon(
            br#"
                threshold = 1
                generate = [{ path = "./include/alice.share" }]
            "#,
            &resolver(),
        )
        .unwrap();
        assert_eq!(
            blueprint.shares()[0].path(),
            PathBuf::from("/tmp/agree/include/alice.share")
        );
    }

    #[test]
    fn does_not_interpolate_process_environment() {
        let result = Blueprint::from_hocon(
            br#"
                threshold = 1
                generate = [{ path = "alice.share", encrypt = { plain = ${HOME} } }]
            "#,
            &resolver(),
        );
        assert!(
            result.is_err(),
            "blueprint parser must not read the process environment"
        );
    }

    #[test]
    fn rejects_invalid_plans() {
        let paths = resolver();
        assert!(Blueprint::try_new(0, vec![spec("a.share")], &paths).is_err());
        assert!(Blueprint::try_new(2, vec![spec("a.share")], &paths).is_err());
        assert!(Blueprint::try_new(1, vec![spec("a.share"), spec("a.share")], &paths).is_err());
        assert!(Blueprint::try_new(1, vec![spec("")], &paths).is_err());
        assert!(Blueprint::from_hocon(
            br#"
                threshold = 1
                generate = [{ path = "a.share", encrypt = { plain = "x", shell = "printf x" } }]
            "#,
            &paths,
        )
        .is_err());
        assert!(Blueprint::from_hocon(
            br#"
                threshold = 1
                generate = [{ path = "a.share", encrypt = { plain = "" } }]
            "#,
            &paths,
        )
        .is_err());
    }

    #[test]
    fn shell_provider_requires_trust_before_execution() {
        let encryption = BlueprintShareEncryption::shell("printf secret".to_owned());
        assert!(encryption.resolve(ShellTrust::Denied).is_err());
        let password = encryption.resolve(ShellTrust::Trusted).unwrap();
        assert_eq!(password.as_str(), "secret");
    }

    fn spec(path: &str) -> ShareSpec {
        ShareSpec {
            path: PathBuf::from(path),
            encrypt: None,
            comment: None,
            include_info: true,
        }
    }
}
