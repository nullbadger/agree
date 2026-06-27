use {
    crate::error::Error,
    anyhow::{
        Context,
        Result,
    },
    path_clean::PathClean,
    serde::Deserialize,
    std::{
        collections::{
            HashMap,
            HashSet,
        },
        fmt,
        path::PathBuf,
        process::{
            Command,
            Stdio,
        },
    },
    zeroize::Zeroize,
};

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct Blueprint {
    pub threshold: usize,
    pub generate: Vec<BlueprintShare>,
}

impl Blueprint {
    pub(crate) fn from_hocon_bytes(bytes: &[u8]) -> Result<Self> {
        let mut text = String::from_utf8(bytes.to_vec()).context("Blueprint is not valid UTF-8")?;
        let result = (|| -> Result<Self> {
            for token in hocon::tokenize(&text).context("Failed to tokenize blueprint")? {
                if token.kind == hocon::TokenKind::Unquoted && token.value == "include" {
                    anyhow::bail!("Blueprint include directives are not allowed");
                }
            }

            hocon::parse_with_env(&text, &HashMap::new())
                .context("Failed to parse blueprint")?
                .deserialize::<Self>()
                .context("Failed to deserialize blueprint")
        })();
        text.zeroize();
        result
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let share_count = self.generate.len();
        if share_count == 0 {
            anyhow::bail!("Blueprint must generate at least one share");
        }
        if share_count > usize::from(u8::MAX) {
            anyhow::bail!("Blueprint generates too many shares: {} > {}", share_count, u8::MAX);
        }
        if self.threshold == 0 {
            anyhow::bail!("Blueprint threshold must be greater than 0");
        }
        if self.threshold > share_count {
            anyhow::bail!(
                "Blueprint threshold {} exceeds generated share count {}",
                self.threshold,
                share_count
            );
        }

        let mut paths = HashSet::new();
        for share in &self.generate {
            if share.path.as_os_str().is_empty() {
                anyhow::bail!("Blueprint share path must not be empty");
            }

            let clean_path = share.path.clean();
            if !paths.insert(clean_path.clone()) {
                anyhow::bail!("Duplicate share output path: {}", clean_path.display());
            }
        }

        Ok(())
    }

    pub(crate) fn zeroize_secrets(&mut self) {
        for share in &mut self.generate {
            if let Some(encrypt) = &mut share.encrypt {
                encrypt.zeroize();
            }
        }
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct BlueprintShare {
    pub path: PathBuf,
    pub encrypt: Option<BlueprintShareEncryption>,
    pub comment: Option<String>,
    pub info: Option<bool>,
}

#[derive(Zeroize)]
pub(crate) enum BlueprintShareEncryption {
    Plain(String),
    Shell(String),
}

impl<'de> Deserialize<'de> for BlueprintShareEncryption {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where D: serde::Deserializer<'de> {
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case", deny_unknown_fields)]
        struct Input {
            plain: Option<String>,
            shell: Option<String>,
        }

        let input = Input::deserialize(deserializer)?;
        match (input.plain, input.shell) {
            | (Some(password), None) => Ok(Self::Plain(password)),
            | (None, Some(script)) => Ok(Self::Shell(script)),
            | (None, None) => Err(serde::de::Error::custom("encrypt requires plain or shell")),
            | (Some(_), Some(_)) => Err(serde::de::Error::custom("encrypt cannot contain both plain and shell")),
        }
    }
}

impl fmt::Debug for BlueprintShareEncryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | BlueprintShareEncryption::Plain(_) => f.write_str("Plain(<redacted>)"),
            | BlueprintShareEncryption::Shell(_) => f.write_str("Shell(<redacted>)"),
        }
    }
}

impl BlueprintShareEncryption {
    pub(crate) fn exec(&self, trust: bool) -> Result<String> {
        match self {
            | BlueprintShareEncryption::Plain(password) => Ok(password.clone()),
            | BlueprintShareEncryption::Shell(script) => {
                if !trust {
                    return Err(Error::NoTrust.into());
                }

                let output = Command::new("sh")
                    .arg("-c")
                    .arg(script)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .output()
                    .context("Failed to execute password provider")?;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    anyhow::bail!("Password provider failed: {}", stderr.trim());
                }

                let value = String::from_utf8(output.stdout).context("Password provider output is not valid UTF-8")?;
                Ok(value.trim_end_matches(['\n', '\r']).to_string())
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Blueprint;

    #[test]
    fn parses_hocon_blueprint() {
        let blueprint = Blueprint::from_hocon_bytes(
            br#"
                threshold = 1
                generate = [
                  { path = "alice.share", encrypt = { plain = "password" }, info = true }
                ]
            "#,
        )
        .expect("blueprint parses");

        assert_eq!(blueprint.threshold, 1);
        assert_eq!(blueprint.generate.len(), 1);
    }

    #[test]
    fn rejects_hocon_includes() {
        assert!(Blueprint::from_hocon_bytes(br#"include "other.conf""#).is_err());
    }
}
