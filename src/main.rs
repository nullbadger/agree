#![forbid(unsafe_code)]

mod archive;
mod args;
mod blueprint;
mod engine;
mod error;
mod reference;

use {
    crate::{
        archive::{
            ArchiveData,
            Base64String,
            Share,
        },
        args::{
            ClapArgumentLoader,
            Command,
            ManualFormat,
            RestoreCommand,
            SplitCommand,
        },
        blueprint::{
            Blueprint,
            BlueprintShare,
        },
        engine::SecretSharingEngine,
        error::Error,
    },
    anyhow::{
        Context,
        Result,
    },
    std::io::Write,
    zeroize::Zeroize,
};

fn get_archive_version() -> String {
    let mut parts = env!("CARGO_PKG_VERSION").split('.');
    let major = parts.next().unwrap_or("0");
    let minor = parts.next().unwrap_or("0");
    format!("{}.{}", major, minor)
}

fn prompt_optional_password() -> Result<Option<String>> {
    let with_encryption = dialoguer::Confirm::new()
        .with_prompt("Encrypt share data with password?")
        .interact()
        .context("Failed to read encryption choice")?;
    if !with_encryption {
        return Ok(None);
    }

    let mut password: String = dialoguer::Password::new()
        .with_prompt("Enter password for share".to_owned())
        .interact()
        .context("Failed to read password")?;
    let mut password_confirm: String = match dialoguer::Password::new()
        .with_prompt("Enter password for confirmation".to_owned())
        .interact()
        .context("Failed to read password confirmation")
    {
        | Ok(password_confirm) => password_confirm,
        | Err(err) => {
            password.zeroize();
            return Err(err);
        },
    };

    if password != password_confirm {
        password.zeroize();
        password_confirm.zeroize();
        return Err(Error::PasswordMismatch.into());
    }

    password_confirm.zeroize();
    Ok(Some(password))
}

fn main() -> Result<()> {
    let cmd = ClapArgumentLoader::load()?;

    match cmd.command {
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
            let builder = reference::ReferenceBuilder::new();
            builder.build_shell_completion(&path, &shell)?;
            Ok(())
        },
        | Command::Split(cmd) => {
            match cmd {
                | SplitCommand::Auto {
                    mut secret_data,
                    mut blueprint,
                    trust,
                    force,
                } => {
                    let parsed_blueprint = Blueprint::from_hocon_bytes(&blueprint);
                    blueprint.zeroize();
                    let mut blueprint = match parsed_blueprint {
                        | Ok(blueprint) => blueprint,
                        | Err(err) => {
                            secret_data.zeroize();
                            return Err(err);
                        },
                    };
                    let engine = SecretSharingEngine::new(get_archive_version());
                    let result = engine.generate(&secret_data, &blueprint, trust, force);
                    blueprint.zeroize_secrets();
                    secret_data.zeroize();
                    result?;
                },
                | SplitCommand::Interactive { mut secret_data, force } => {
                    let mut blueprint = Blueprint {
                        threshold: 0,
                        generate: Vec::<_>::new(),
                    };
                    let result = (|| -> Result<()> {
                        blueprint.threshold = dialoguer::Input::new()
                            .with_prompt("Enter threshold")
                            .interact()
                            .context("Failed to read threshold")?;
                        println!();

                        loop {
                            println!("--- Entering share information ---");

                            let path: String = dialoguer::Input::new()
                                .with_prompt("Save to file")
                                .interact()
                                .context("Failed to read share path")?;
                            let with_secret_info = dialoguer::Confirm::new()
                                .with_prompt("Include secret info (num shares / threshold) in share?")
                                .interact()
                                .context("Failed to read share info choice")?;

                            let with_comment = dialoguer::Confirm::new()
                                .with_prompt("Add comment to share?")
                                .interact()
                                .context("Failed to read comment choice")?;
                            let comment: Option<String> = if with_comment {
                                Some(
                                    dialoguer::Input::new()
                                        .with_prompt("Comment")
                                        .interact()
                                        .context("Failed to read comment")?,
                                )
                            } else {
                                None
                            };
                            let password = prompt_optional_password()?;

                            blueprint.generate.push(BlueprintShare {
                                path: path.into(),
                                encrypt: password.map(blueprint::BlueprintShareEncryption::Plain),
                                info: Some(with_secret_info),
                                comment,
                            });
                            println!("--- --- ---");
                            println!();
                            if !dialoguer::Confirm::new()
                                .with_prompt("Add another share?")
                                .interact()
                                .context("Failed to read continuation choice")?
                            {
                                break;
                            }
                            println!();
                        }

                        let engine = SecretSharingEngine::new(get_archive_version());
                        engine.generate(&secret_data, &blueprint, false, force)
                    })();
                    blueprint.zeroize_secrets();
                    secret_data.zeroize();
                    result?;
                },
            }
            Ok(())
        },
        | Command::Restore(cmd) => {
            let engine = SecretSharingEngine::new(get_archive_version());
            let mut secret = match cmd {
                | RestoreCommand::Auto { shares } => engine.restore(&shares, false)?,
                | RestoreCommand::Interactive { shares } => engine.restore(&shares, true)?,
            };
            let result = std::io::stdout()
                .write_all(&secret)
                .context("Failed to write restored secret to stdout");
            secret.zeroize();
            result?;
            Ok(())
        },
        | Command::Info { share } => {
            let engine = SecretSharingEngine::new(get_archive_version());
            let archive = engine.info(&share.1)?;
            let archive_data = archive.decode_data()?;
            println!("Version:\t{}", archive.version);
            println!("UID:\t\t{}", archive.uid);
            println!("PID:\t\t{}", archive.pid);
            println!(
                "Data:\n=== BEGIN DATA ===\n{}\n=== END DATA ===",
                serde_json::to_string_pretty(&archive_data.redacted_json())?
            );
            Ok(())
        },
        | Command::Edit { share } => {
            let engine = SecretSharingEngine::new(get_archive_version());

            let mut archive = engine.info(&share.1)?;
            engine.validate_archive_version(&archive)?;
            let archive_data = archive.decode_data()?;
            let archive_info = archive_data.info;
            let (mut share_data, auth) = engine.read_share_payload(archive_data.share, true)?;
            let password = match prompt_optional_password() {
                | Ok(password) => password,
                | Err(err) => {
                    share_data.zeroize();
                    return Err(err);
                },
            };

            let result = (|| -> Result<()> {
                let new_share = match password {
                    | Some(mut password) => engine.lock_with_password(&share_data, &mut password, auth)?,
                    | None => {
                        Share::Plain {
                            data: Base64String::new(&share_data),
                            auth,
                        }
                    },
                };
                let archive_data = ArchiveData {
                    share: new_share,
                    info: archive_info,
                };
                archive.data = Base64String::new(
                    serde_json::to_vec(&archive_data).context("Failed to serialize edited archive data")?,
                );
                SecretSharingEngine::write_archive(&share.0, &archive, true)
            })();
            share_data.zeroize();
            result?;

            Ok(())
        },
    }
}
