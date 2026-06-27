use {
    crate::error::Error,
    anyhow::{
        Context,
        Result,
    },
    clap::{
        Arg,
        ArgAction,
    },
    path_clean::PathClean,
    std::{
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
            | InputFileKind::Secret => MAX_SECRET_FILE_BYTES,
            | InputFileKind::Blueprint => MAX_BLUEPRINT_FILE_BYTES,
            | InputFileKind::Share => MAX_SHARE_FILE_BYTES,
        }
    }

    fn label(self) -> &'static str {
        match self {
            | InputFileKind::Secret => "secret",
            | InputFileKind::Blueprint => "blueprint",
            | InputFileKind::Share => "share",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Privilege {
    Normal,
    Experimental,
}

#[derive(Debug)]
pub(crate) struct CallArgs {
    pub privileges: Privilege,
    pub command: Command,
}

impl CallArgs {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.privileges == Privilege::Experimental {
            return Ok(());
        }

        match &self.command {
            | Command::Info { .. } => Err(Error::Experimental("info".to_owned()).into()),
            | Command::Edit { .. } => Err(Error::Experimental("edit".to_owned()).into()),
            | _ => Ok(()),
        }
    }
}

#[derive(Debug)]
pub(crate) enum ManualFormat {
    Manpages,
    Markdown,
}

#[derive(Debug)]
pub(crate) enum Command {
    Manual { path: PathBuf, format: ManualFormat },
    Autocomplete { path: PathBuf, shell: clap_complete::Shell },
    Split(SplitCommand),
    Restore(RestoreCommand),
    Info { share: (PathBuf, Vec<u8>) },
    Edit { share: (PathBuf, Vec<u8>) },
}

#[derive(Debug)]
pub(crate) enum SplitCommand {
    Auto {
        secret_data: Vec<u8>,
        blueprint: Vec<u8>,
        trust: bool,
        force: bool,
    },
    Interactive {
        secret_data: Vec<u8>,
        force: bool,
    },
}

#[derive(Debug)]
pub(crate) enum RestoreCommand {
    Auto { shares: Vec<(PathBuf, Vec<u8>)> },
    Interactive { shares: Vec<(PathBuf, Vec<u8>)> },
}

pub(crate) struct ClapArgumentLoader {}

impl ClapArgumentLoader {
    fn get_absolute_path(matches: &clap::ArgMatches, name: &str) -> Result<PathBuf> {
        let path_str: &String = matches
            .get_one(name)
            .ok_or_else(|| Error::Argument(format!("missing path argument: {name}")))?;
        let path = Path::new(path_str);
        if path.is_absolute() {
            Ok(path.to_path_buf().clean())
        } else {
            Ok(std::env::current_dir()
                .context("Failed to get current directory")?
                .join(path)
                .clean())
        }
    }

    fn read_file(path: &Path, kind: InputFileKind) -> Result<Vec<u8>> {
        let file = File::open(path).with_context(|| format!("Failed to open file: {}", path.display()))?;
        let limit = kind.limit();
        let mut reader = file.take(limit + 1);
        let mut data = Vec::new();
        reader
            .read_to_end(&mut data)
            .with_context(|| format!("Failed to read file: {}", path.display()))?;
        if data.len() as u64 > limit {
            anyhow::bail!(
                "{} file is too large: {} exceeds {} bytes",
                kind.label(),
                path.display(),
                limit
            );
        }
        Ok(data)
    }

    pub(crate) fn root_command() -> clap::Command {
        clap::Command::new(env!("CARGO_PKG_NAME"))
            .version(env!("CARGO_PKG_VERSION"))
            .about(env!("CARGO_PKG_DESCRIPTION"))
            .author("Alexander Weber <alexanderh.weber@outlook.com>")
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
                    .arg(clap::Arg::new("out").short('o').long("out").required(true))
                    .arg(
                        clap::Arg::new("format")
                            .short('f')
                            .long("format")
                            .value_parser(["manpages", "markdown"])
                            .required(true),
                    ),
            )
            .subcommand(
                clap::Command::new("autocomplete")
                    .about("Renders shell completion scripts.")
                    .arg(clap::Arg::new("out").short('o').long("out").required(true))
                    .arg(
                        clap::Arg::new("shell")
                            .short('s')
                            .long("shell")
                            .value_parser(["bash", "zsh", "fish", "elvish", "powershell"])
                            .required(true),
                    ),
            )
            .subcommand(
                clap::Command::new("split")
                    .about("Split a secret.")
                    .arg(
                        clap::Arg::new("interactive")
                            .long("interactive")
                            .short('i')
                            .help("Interactive mode.")
                            .action(ArgAction::SetTrue)
                            .conflicts_with("blueprint"),
                    )
                    .arg(
                        clap::Arg::new("secret")
                            .long("secret")
                            .short('s')
                            .help("Path to the file containing the secret.")
                            .required(true),
                    )
                    .arg(
                        clap::Arg::new("blueprint")
                            .long("blueprint")
                            .short('b')
                            .help("Path to the blueprint file.")
                            .required_unless_present("interactive"),
                    )
                    .arg(
                        clap::Arg::new("trust")
                            .long("trust")
                            .short('t')
                            .help("Allow shell invocations from blueprint scripts.")
                            .action(ArgAction::SetTrue),
                    )
                    .arg(
                        clap::Arg::new("force")
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
                        clap::Arg::new("share")
                            .long("share")
                            .short('s')
                            .help("Path to a share file.")
                            .required(true)
                            .action(ArgAction::Append),
                    )
                    .arg(
                        clap::Arg::new("interactive")
                            .long("interactive")
                            .short('i')
                            .help("Interactive mode.")
                            .action(ArgAction::SetTrue),
                    ),
            )
            .subcommand(
                clap::Command::new("info")
                    .about("Display information about a share.")
                    .arg(
                        clap::Arg::new("share")
                            .long("share")
                            .short('s')
                            .help("Path to a share file.")
                            .required(true),
                    ),
            )
            .subcommand(
                clap::Command::new("edit").about("Edit the share.").arg(
                    clap::Arg::new("share")
                        .long("share")
                        .short('s')
                        .help("Path to a share file.")
                        .required(true),
                ),
            )
    }

    pub(crate) fn load() -> Result<CallArgs> {
        let command = Self::root_command().get_matches();

        let privileges = if command.get_flag("experimental") {
            Privilege::Experimental
        } else {
            Privilege::Normal
        };

        let cmd = if let Some(subc) = command.subcommand_matches("man") {
            Command::Manual {
                path: Self::get_absolute_path(subc, "out")?,
                format: match subc
                    .get_one::<String>("format")
                    .ok_or_else(|| Error::Argument("missing format argument".to_owned()))?
                    .as_str()
                {
                    | "manpages" => ManualFormat::Manpages,
                    | "markdown" => ManualFormat::Markdown,
                    | _ => return Err(Error::Argument("unknown format".into()).into()),
                },
            }
        } else if let Some(subc) = command.subcommand_matches("autocomplete") {
            Command::Autocomplete {
                path: Self::get_absolute_path(subc, "out")?,
                shell: clap_complete::Shell::from_str(
                    subc.get_one::<String>("shell")
                        .ok_or_else(|| Error::Argument("missing shell argument".to_owned()))?
                        .as_str(),
                )
                .map_err(|e| anyhow::anyhow!("Failed to parse shell: {}", e))?,
            }
        } else if let Some(subc) = command.subcommand_matches("split") {
            let secret_path = Self::get_absolute_path(subc, "secret")?;
            if subc.get_flag("interactive") {
                Command::Split(SplitCommand::Interactive {
                    secret_data: Self::read_file(&secret_path, InputFileKind::Secret)?,
                    force: subc.get_flag("force"),
                })
            } else {
                let blueprint_path = Self::get_absolute_path(subc, "blueprint")?;
                Command::Split(SplitCommand::Auto {
                    secret_data: Self::read_file(&secret_path, InputFileKind::Secret)?,
                    blueprint: Self::read_file(&blueprint_path, InputFileKind::Blueprint)?,
                    trust: subc.get_flag("trust"),
                    force: subc.get_flag("force"),
                })
            }
        } else if let Some(subc) = command.subcommand_matches("restore") {
            let shares_args = subc
                .get_many::<String>("share")
                .ok_or_else(|| Error::Argument("missing share argument".to_owned()))?;
            let mut shares = Vec::<(PathBuf, Vec<u8>)>::new();
            for share in shares_args {
                let path = if Path::new(share).is_absolute() {
                    PathBuf::from(share).clean()
                } else {
                    std::env::current_dir()
                        .context("Failed to get current directory")?
                        .join(share)
                        .clean()
                };
                shares.push((path.clone(), Self::read_file(&path, InputFileKind::Share)?));
            }

            if subc.get_flag("interactive") {
                Command::Restore(RestoreCommand::Interactive { shares })
            } else {
                Command::Restore(RestoreCommand::Auto { shares })
            }
        } else if let Some(subc) = command.subcommand_matches("info") {
            let path = Self::get_absolute_path(subc, "share")?;
            Command::Info {
                share: (path.clone(), Self::read_file(&path, InputFileKind::Share)?),
            }
        } else if let Some(subc) = command.subcommand_matches("edit") {
            let path = Self::get_absolute_path(subc, "share")?;
            Command::Edit {
                share: (path.clone(), Self::read_file(&path, InputFileKind::Share)?),
            }
        } else {
            return Err(Error::UnknownCommand.into());
        };

        let callargs = CallArgs {
            privileges,
            command: cmd,
        };

        callargs.validate()?;
        Ok(callargs)
    }
}
