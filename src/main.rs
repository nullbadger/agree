#![forbid(unsafe_code)]

mod archive;
mod args;
mod blueprint;
mod crypto;
mod engine;
mod error;
mod paths;
mod policy;
mod prompt;
mod reference;
mod scheme;
mod secret;
mod store;

use {
    crate::{
        archive::{
            Archive,
            ArchiveVersion,
        },
        args::{
            ClapArgumentLoader,
            Command,
            ExperimentalCommand,
            ManualFormat,
            SplitCommand,
        },
        engine::SecretSharingEngine,
        policy::ShellTrust,
        prompt::Console,
    },
    anyhow::{
        Context,
        Result,
    },
    std::io::Write,
};

fn main() -> Result<()> {
    App::run()
}

struct App;

impl App {
    fn run() -> Result<()> {
        let args = ClapArgumentLoader::load()?;
        let engine = SecretSharingEngine::new(ArchiveVersion::current());
        match args.command {
            | Command::Manual { path, format } => {
                std::fs::create_dir_all(&path)
                    .with_context(|| format!("Failed to create directory: {}", path.display()))?;
                let builder = reference::ReferenceBuilder::new();
                match format {
                    | ManualFormat::Manpages => builder.build_manpages(&path)?,
                    | ManualFormat::Markdown => builder.build_markdown(&path)?,
                }
                Ok(())
            },
            | Command::Autocomplete { path, shell } => {
                std::fs::create_dir_all(&path)
                    .with_context(|| format!("Failed to create directory: {}", path.display()))?;
                reference::ReferenceBuilder::new().build_shell_completion(&path, &shell)?;
                Ok(())
            },
            | Command::Split(SplitCommand::Blueprint {
                secret,
                blueprint,
                trust,
                overwrite,
            }) => {
                engine.split(&secret, &blueprint, trust, overwrite)?;
                Ok(())
            },
            | Command::Split(SplitCommand::Interactive { secret, overwrite }) => {
                let blueprint = Console::prompt_blueprint(&args.paths)?;
                engine.split(&secret, &blueprint, ShellTrust::Denied, overwrite)?;
                Ok(())
            },
            | Command::Restore(command) => {
                let mut console = Console;
                let secret = engine.restore(&command.shares, command.prompt, &mut console)?;
                std::io::stdout()
                    .write_all(secret.as_slice())
                    .context("Failed to write restored secret to stdout")?;
                Ok(())
            },
            | Command::Experimental(ExperimentalCommand::Info(share)) => {
                let archive = Archive::parse(share.bytes())
                    .with_context(|| format!("Failed to parse share archive: {}", share.path().display()))?;
                println!("{}", archive.report()?);
                Ok(())
            },
            | Command::Experimental(ExperimentalCommand::Edit(share)) => {
                let mut console = Console;
                let new_password = Console::optional_password()?;
                engine.edit(&share, new_password, &mut console)?;
                Ok(())
            },
        }
    }
}
