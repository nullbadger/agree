use {
    anyhow::{
        Context,
        Result,
    },
    path_clean::PathClean,
    std::{
        env,
        path::{
            Path,
            PathBuf,
        },
    },
};

/// Resolves user-supplied paths once, at the process boundary.
///
/// Business logic receives already-resolved paths and does not read `HOME` or
/// the working directory.
#[derive(Clone, Debug)]
pub(crate) struct PathResolver {
    cwd: PathBuf,
    home: Option<PathBuf>,
}

impl PathResolver {
    pub(crate) fn from_process() -> Result<Self> {
        Ok(Self {
            cwd: env::current_dir().context("Failed to get current directory")?,
            home: env::var_os("HOME").map(PathBuf::from),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_cwd(cwd: PathBuf) -> Self {
        Self { cwd, home: None }
    }

    pub(crate) fn resolve(&self, path: impl AsRef<Path>) -> Result<PathBuf> {
        let expanded = expand_tilde(path.as_ref(), self.home.as_deref())?;
        let absolute = if expanded.is_absolute() {
            expanded
        } else {
            self.cwd.join(expanded)
        };
        Ok(absolute.clean())
    }
}

fn expand_tilde(path: &Path, home: Option<&Path>) -> Result<PathBuf> {
    let Some(text) = path.to_str() else {
        return Ok(path.to_path_buf());
    };
    if text == "~" {
        return home
            .context("cannot expand '~': HOME is not set")
            .map(Path::to_path_buf);
    }
    if let Some(rest) = text.strip_prefix("~/") {
        let home = home.context("cannot expand '~': HOME is not set")?;
        return Ok(home.join(rest));
    }
    Ok(path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use {
        super::PathResolver,
        std::path::PathBuf,
    };

    #[test]
    fn resolves_relative_paths_against_the_injected_cwd() {
        let resolver = PathResolver::with_cwd(PathBuf::from("/tmp/agree"));
        assert_eq!(
            resolver.resolve("alice.share").unwrap(),
            PathBuf::from("/tmp/agree/alice.share")
        );
        assert_eq!(
            resolver.resolve("/var/alice.share").unwrap(),
            PathBuf::from("/var/alice.share")
        );
    }

    #[test]
    fn expands_tilde_against_the_injected_home() {
        let resolver = PathResolver {
            cwd: PathBuf::from("/tmp/agree"),
            home: Some(PathBuf::from("/Users/test")),
        };
        assert_eq!(
            resolver.resolve("~/shares/alice.share").unwrap(),
            PathBuf::from("/Users/test/shares/alice.share")
        );
    }
}
