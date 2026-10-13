use {
    crate::{
        archive::ShareFile,
        blueprint::Blueprint,
        error::Error,
        paths::PathResolver,
        policy::{
            Overwrite,
            PromptMode,
            ShellTrust,
        },
        secret::SecretBytes,
    },
    anyhow::{
        Context,
        Result,
    },
    clap::{
        value_parser,
        Arg,
        ArgAction,
    },
    std::{
        collections::HashSet,
        fs::File,
        io::Read,
        path::{
            Path,
            PathBuf,
        },
        str::FromStr,
    },
};

const MAX_SECRET_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_BLUEPRINT_FILE_BYTES: u64 = 1024 * 1024;
const MAX_SHARE_FILE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Copy)]
enum InputFileKind {
    Secret,
    Blueprint,
    Share,
}

impl InputFileKind {
    fn limit(self) -> u64 {
        match self {
            | Self::Secret => MAX_SECRET_FILE_BYTES,
            | Self::Blueprint => MAX_BLUEPRINT_FILE_BYTES,
            | Self::Share => MAX_SHARE_FILE_BYTES,
        }
    }

    fn label(self) -> &'static str {
        match self {
            | Self::Secret => "secret",
            | Self::Blueprint => "blueprint",
            | Self::Share => "share",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManualFormat {
    Manpages,
    Markdown,
}

impl FromStr for ManualFormat {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            | "manpages" => Ok(Self::Manpages),
            | "markdown" => Ok(Self::Markdown),
            | other => Err(format!("unknown format: {other}")),
        }
    }
}

pub(crate) struct CallArgs {
    pub(crate) paths: PathResolver,
    pub(crate) command: Command,
}

pub(crate) enum Command {
    Manual {
        path: PathBuf,
        format: ManualFormat,
    },
    Autocomplete {
        path: PathBuf,
        shell: clap_complete::Shell,
    },
    Split(SplitCommand),
    Restore(RestoreCommand),
    /// Produced only when `--experimental` is set. The loader is the gate.
    Experimental(ExperimentalCommand),
}

pub(crate) enum ExperimentalCommand {
    Info(ShareFile),
    Edit(ShareFile),
}

pub(crate) enum SplitCommand {
    Blueprint {
        secret: SecretBytes,
        blueprint: Blueprint,
        trust: ShellTrust,
        overwrite: Overwrite,
    },
    Interactive {
        secret: SecretBytes,
        overwrite: Overwrite,
    },
}

pub(crate) struct RestoreCommand {
    pub(crate) shares: Vec<ShareFile>,
    pub(crate) prompt: PromptMode,
}

pub(crate) struct ClapArgumentLoader;

impl ClapArgumentLoader {
    pub(crate) fn root_command() -> clap::Command {
        clap::Command::new(env!("CARGO_PKG_NAME"))
            .version(env!("CARGO_PKG_VERSION"))
            .about(env!("CARGO_PKG_DESCRIPTION"))
            .author(env!("CARGO_PKG_AUTHORS"))
            .propagate_version(true)
            .subcommand_required(true)
            .args([Arg::new("experimental")
                .short('e')
                .long("experimental")
                .help("Enables experimental features.")
                .action(ArgAction::SetTrue)])
            .subcommand(
                clap::Command::new("man")
                    .about("Renders the manual.")
                    .arg(Arg::new("out").short('o').long("out").required(true))
                    .arg(
                        Arg::new("format")
                            .short('f')
                            .long("format")
                            .value_parser(["manpages", "markdown"])
                            .required(true),
                    ),
            )
            .subcommand(
                clap::Command::new("autocomplete")
                    .about("Renders shell completion scripts.")
                    .arg(Arg::new("out").short('o').long("out").required(true))
                    .arg(
                        Arg::new("shell")
                            .short('s')
                            .long("shell")
                            .value_parser(value_parser!(clap_complete::Shell))
                            .required(true),
                    ),
            )
            .subcommand(
                clap::Command::new("split")
                    .about("Split a secret.")
                    .arg(
                        Arg::new("interactive")
                            .long("interactive")
                            .short('i')
                            .help("Prompt for share destinations, threshold, and passwords.")
                            .action(ArgAction::SetTrue)
                            .conflicts_with("blueprint"),
                    )
                    .arg(
                        Arg::new("secret")
                            .long("secret")
                            .short('s')
                            .help("Path to the file containing the secret.")
                            .required(true),
                    )
                    .arg(
                        Arg::new("blueprint")
                            .long("blueprint")
                            .short('b')
                            .help("Path to the blueprint file.")
                            .required_unless_present("interactive"),
                    )
                    .arg(
                        Arg::new("trust")
                            .long("trust")
                            .short('t')
                            .help("Run shell password providers from the blueprint.")
                            .action(ArgAction::SetTrue),
                    )
                    .arg(
                        Arg::new("force")
                            .long("force")
                            .short('f')
                            .help("Overwrite existing share files.")
                            .action(ArgAction::SetTrue),
                    ),
            )
            .subcommand(
                clap::Command::new("restore")
                    .about("Restores a secret from shares.")
                    .arg(
                        Arg::new("share")
                            .long("share")
                            .short('s')
                            .help("Path to a share file.")
                            .required(true)
                            .action(ArgAction::Append),
                    )
                    .arg(
                        Arg::new("interactive")
                            .long("interactive")
                            .short('i')
                            .help("Prompt for passwords of encrypted shares.")
                            .action(ArgAction::SetTrue),
                    ),
            )
            .subcommand(
                clap::Command::new("info")
                    .about("Display redacted information about a share.")
                    .arg(
                        Arg::new("share")
                            .long("share")
                            .short('s')
                            .help("Path to a share file.")
                            .required(true),
                    ),
            )
            .subcommand(
                clap::Command::new("edit")
                    .about("Change or remove a share password.")
                    .arg(
                        Arg::new("share")
                            .long("share")
                            .short('s')
                            .help("Path to a share file.")
                            .required(true),
                    ),
            )
    }

    pub(crate) fn load() -> Result<CallArgs> {
        let matches = Self::root_command().get_matches();
        Self::from_matches(&matches, PathResolver::from_process()?)
    }

    fn from_matches(matches: &clap::ArgMatches, paths: PathResolver) -> Result<CallArgs> {
        let experimental = matches.get_flag("experimental");
        let command = if let Some(sub) = matches.subcommand_matches("man") {
            Command::Manual {
                path: paths.resolve(required_str(sub, "out")?)?,
                format: ManualFormat::from_str(required_str(sub, "format")?).map_err(|err| anyhow::anyhow!(err))?,
            }
        } else if let Some(sub) = matches.subcommand_matches("autocomplete") {
            Command::Autocomplete {
                path: paths.resolve(required_str(sub, "out")?)?,
                shell: *sub
                    .get_one::<clap_complete::Shell>("shell")
                    .context("missing shell argument")?,
            }
        } else if let Some(sub) = matches.subcommand_matches("split") {
            let secret = SecretBytes::new(Self::read_file(
                &paths.resolve(required_str(sub, "secret")?)?,
                InputFileKind::Secret,
            )?);
            let overwrite = Overwrite::from_flag(sub.get_flag("force"));
            if sub.get_flag("interactive") {
                Command::Split(SplitCommand::Interactive { secret, overwrite })
            } else {
                let blueprint_bytes = SecretBytes::new(Self::read_file(
                    &paths.resolve(required_str(sub, "blueprint")?)?,
                    InputFileKind::Blueprint,
                )?);
                let blueprint = Blueprint::from_hocon(blueprint_bytes.as_slice(), &paths)?;
                Command::Split(SplitCommand::Blueprint {
                    secret,
                    blueprint,
                    trust: ShellTrust::from_flag(sub.get_flag("trust")),
                    overwrite,
                })
            }
        } else if let Some(sub) = matches.subcommand_matches("restore") {
            Command::Restore(RestoreCommand {
                shares: Self::read_shares(sub, &paths)?,
                prompt: PromptMode::from_flag(sub.get_flag("interactive")),
            })
        } else if let Some(sub) = matches.subcommand_matches("info") {
            ensure_experimental(experimental, "info")?;
            Command::Experimental(ExperimentalCommand::Info(Self::read_one_share(sub, &paths)?))
        } else if let Some(sub) = matches.subcommand_matches("edit") {
            ensure_experimental(experimental, "edit")?;
            Command::Experimental(ExperimentalCommand::Edit(Self::read_one_share(sub, &paths)?))
        } else {
            anyhow::bail!("unknown command");
        };

        Ok(CallArgs { paths, command })
    }

    fn read_one_share(matches: &clap::ArgMatches, paths: &PathResolver) -> Result<ShareFile> {
        let path = paths.resolve(required_str(matches, "share")?)?;
        let bytes = Self::read_file(&path, InputFileKind::Share)?;
        Ok(ShareFile::new(path, bytes))
    }

    fn read_shares(matches: &clap::ArgMatches, paths: &PathResolver) -> Result<Vec<ShareFile>> {
        let args = matches.get_many::<String>("share").context("missing share argument")?;
        let mut files = Vec::new();
        let mut seen = HashSet::new();
        for share in args {
            let path = paths.resolve(share)?;
            if !seen.insert(path.clone()) {
                anyhow::bail!("duplicate share path: {}", path.display());
            }
            let bytes = Self::read_file(&path, InputFileKind::Share)?;
            files.push(ShareFile::new(path, bytes));
        }
        Ok(files)
    }

    fn read_file(path: &Path, kind: InputFileKind) -> Result<Vec<u8>> {
        let file = File::open(path).with_context(|| format!("Failed to open file: {}", path.display()))?;
        let limit = kind.limit();
        let mut reader = file.take(limit.saturating_add(1));
        let mut data = Vec::new();
        reader
            .read_to_end(&mut data)
            .with_context(|| format!("Failed to read file: {}", path.display()))?;
        let len = u64::try_from(data.len()).unwrap_or(u64::MAX);
        if len > limit {
            anyhow::bail!(
                "{} file is too large: {} exceeds {limit} bytes",
                kind.label(),
                path.display()
            );
        }
        Ok(data)
    }
}

fn required_str<'a>(matches: &'a clap::ArgMatches, name: &str) -> Result<&'a str> {
    matches
        .get_one::<String>(name)
        .map(String::as_str)
        .with_context(|| format!("missing {name} argument"))
}

fn ensure_experimental(enabled: bool, command: &'static str) -> Result<()> {
    if enabled {
        return Ok(());
    }
    Err(Error::Experimental { command }.into())
}

#[cfg(test)]
mod tests {
    use {
        super::{
            ensure_experimental,
            ClapArgumentLoader,
            InputFileKind,
        },
        std::{
            fs,
            path::PathBuf,
        },
        uuid::Uuid,
    };

    #[test]
    fn experimental_commands_are_rejected_without_the_flag() {
        assert!(ensure_experimental(false, "info").is_err());
        assert!(ensure_experimental(true, "edit").is_ok());
    }

    #[test]
    fn rejects_files_over_the_limit() {
        struct TempDir(std::path::PathBuf);
        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let dir = TempDir(std::env::temp_dir().join(format!("agree-args-{}", Uuid::new_v4())));
        fs::create_dir_all(&dir.0).unwrap();
        let path = dir.0.join("blueprint.conf");
        fs::write(&path, vec![b'a'; (1024 * 1024) + 1]).unwrap();
        let err = ClapArgumentLoader::read_file(&path, InputFileKind::Blueprint).unwrap_err();
        assert!(err.to_string().contains("too large"));
    }

    #[test]
    fn info_without_experimental_is_rejected_by_clap_load() {
        let matches = ClapArgumentLoader::root_command()
            .try_get_matches_from(["agree", "info", "-s", "missing.share"])
            .unwrap();
        let Err(err) =
            ClapArgumentLoader::from_matches(&matches, crate::paths::PathResolver::with_cwd(PathBuf::from(".")))
        else {
            panic!("info without --experimental must fail");
        };
        assert!(err.to_string().contains("--experimental"));
    }
}
