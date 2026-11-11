use {
    crate::location::Locator,
    anyhow::Result,
    clap::{
        Args,
        Parser,
        Subcommand,
    },
    std::path::PathBuf,
};

#[derive(Parser)]
#[command(name = "agree", version, about = "Split a secret so a threshold of shares can restore it.", author)]
pub(crate) struct Cli {
    /// Echo the YubiKey PIN and management key, then print the captured values
    /// on stderr. Share passwords stay hidden.
    #[arg(long, global = true)]
    pub(crate) debug: bool,
    #[command(subcommand)]
    pub(crate) command: Command,
}

impl Cli {
    pub(crate) fn parse_args() -> Self {
        Self::parse()
    }

    pub(crate) fn root_command() -> clap::Command {
        <Self as clap::CommandFactory>::command()
    }
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Split a secret from stdin into shares.
    Split(SplitArgs),
    /// Restore a secret to stdout from a sealed file and a threshold of shares.
    Restore(RestoreArgs),
    /// List attached hardware this build can open. Nothing is written.
    Devices,
    /// Render the manual.
    Man(ManArgs),
    /// Render shell completion scripts.
    Autocomplete(AutocompleteArgs),
}

#[derive(Args)]
pub(crate) struct SplitArgs {
    /// Shares required to restore. For a break-glass signing key, use 3 of 5.
    #[arg(short, long)]
    pub(crate) threshold: u8,
    /// Data-key size in bytes. Must be a multiple of 32, from 32 to 1024. Each
    /// 32 bytes is one encryption layer. Default 32.
    #[arg(long, default_value_t = 32)]
    pub(crate) key_bytes: u16,
    /// Read the data key from this path instead of generating it. A file or
    /// pipe of exactly `--key-bytes` bytes, not a command and not a
    /// `device:` or `yubikey:` location. Stdin remains the secret.
    #[arg(long)]
    pub(crate) key_file: Option<String>,
    /// Where to write the sealed secret. Not a share, and not secret by itself.
    #[arg(long)]
    pub(crate) sealed: String,
    /// Where to write one share. Repeat once per share. File, `device:PATH`, or
    /// `yubikey:[serial/]OBJECT`.
    #[arg(long, required = true)]
    pub(crate) share: Vec<String>,
    /// Prompt on the terminal for an optional password per share. Stdin is the
    /// secret, so passwords cannot be read from it.
    #[arg(long)]
    pub(crate) protect: bool,
    /// YubiKey management key as 48 hex characters, used for every key in this
    /// command. Omit to prompt once per YubiKey; an empty answer uses the
    /// factory key. The PIN is prompted on the terminal.
    #[arg(long)]
    pub(crate) management_key: Option<String>,
    /// Overwrite an existing file or YubiKey object. Required for `device:`
    /// destinations.
    #[arg(short, long)]
    pub(crate) force: bool,
}

#[derive(Args)]
pub(crate) struct RestoreArgs {
    /// Sealed secret produced by split.
    #[arg(long)]
    pub(crate) sealed: String,
    /// Share to restore from. Repeat until the threshold is met.
    #[arg(long, required = true)]
    pub(crate) share: Vec<String>,
    /// Read one password line per share from stdin. An empty line means that
    /// share is unprotected. The secret is written to stdout after these lines
    /// are consumed.
    #[arg(long)]
    pub(crate) password_stdin: bool,
    /// Read one PIN line per YubiKey location, in `--share` order, then one
    /// more if `--sealed` is a YubiKey. Password lines come after those PIN
    /// lines.
    #[arg(long)]
    pub(crate) pin_stdin: bool,
    /// YubiKey management key as 48 hex characters. Defaults to the factory
    /// key.
    #[arg(long)]
    pub(crate) management_key: Option<String>,
}

#[derive(Args)]
pub(crate) struct ManArgs {
    #[arg(short, long)]
    pub(crate) out: PathBuf,
    #[arg(short = 'f', long, value_parser = ["manpages", "markdown"])]
    pub(crate) format: String,
}

#[derive(Args)]
pub(crate) struct AutocompleteArgs {
    #[arg(short, long)]
    pub(crate) out: PathBuf,
    #[arg(short, long)]
    pub(crate) shell: clap_complete::Shell,
}

pub(crate) fn load() -> Result<(Cli, Locator)> {
    Ok((Cli::parse_args(), Locator::from_process()?))
}
