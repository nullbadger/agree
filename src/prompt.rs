use {
    crate::{
        blueprint::{
            Blueprint,
            BlueprintShareEncryption,
            ShareSpec,
        },
        error::Error,
        paths::PathResolver,
        secret::Password,
    },
    anyhow::{
        Context,
        Result,
    },
};

/// Asks the operator for a share password. Engine code depends on this, not on
/// a terminal crate.
pub(crate) trait PasswordPrompt {
    fn password(&mut self, prompt: &str) -> Result<Password>;
}

/// Terminal prompts for split, restore, and edit.
pub(crate) struct Console;

impl Console {
    pub(crate) fn optional_password() -> Result<Option<Password>> {
        if !confirm("Encrypt share data with password?")? {
            return Ok(None);
        }
        loop {
            let password = read_password("Enter password for share")?;
            let confirmation = read_password("Enter password for confirmation")?;
            if password.as_str() == confirmation.as_str() {
                return Ok(Some(password));
            }
            eprintln!("{}", Error::PasswordMismatch);
        }
    }

    pub(crate) fn prompt_blueprint(paths: &PathResolver) -> Result<Blueprint> {
        let threshold = input_threshold()?;
        println!();
        let mut shares = Vec::new();
        loop {
            println!("--- Entering share information ---");
            let path = input_path()?;
            let include_info = confirm("Include secret info (num shares / threshold) in share?")?;
            let comment = if confirm("Add comment to share?")? {
                Some(input_string("Comment")?)
            } else {
                None
            };
            let encrypt = Self::optional_password()?.map(BlueprintShareEncryption::plain);
            shares.push(ShareSpec {
                path: path.into(),
                encrypt,
                comment,
                include_info,
            });
            println!("--- --- ---");
            println!();
            if !confirm("Add another share?")? {
                break;
            }
            println!();
        }
        Blueprint::try_new(threshold, shares, paths)
    }
}

impl PasswordPrompt for Console {
    fn password(&mut self, prompt: &str) -> Result<Password> {
        read_password(prompt)
    }
}

fn confirm(prompt: &str) -> Result<bool> {
    dialoguer::Confirm::new()
        .with_prompt(prompt)
        .interact()
        .with_context(|| format!("Failed to read {prompt}"))
}

fn input_string(prompt: &str) -> Result<String> {
    dialoguer::Input::<String>::new()
        .with_prompt(prompt)
        .interact()
        .with_context(|| format!("Failed to read {prompt}"))
}

fn input_path() -> Result<String> {
    dialoguer::Input::<String>::new()
        .with_prompt("Save to file")
        .validate_with(|value: &String| -> Result<(), &str> {
            if value.trim().is_empty() {
                Err("share path must not be empty")
            } else {
                Ok(())
            }
        })
        .interact()
        .context("Failed to read share path")
}

fn input_threshold() -> Result<usize> {
    dialoguer::Input::<usize>::new()
        .with_prompt("Enter threshold")
        .validate_with(|value: &usize| -> Result<(), &str> {
            if *value == 0 {
                Err("threshold must be greater than 0")
            } else {
                Ok(())
            }
        })
        .interact()
        .context("Failed to read threshold")
}

fn read_password(prompt: &str) -> Result<Password> {
    loop {
        let value = dialoguer::Password::new()
            .with_prompt(prompt)
            .interact()
            .context("Failed to read password")?;
        match Password::new(value) {
            | Ok(password) => return Ok(password),
            | Err(err) => eprintln!("{err}"),
        }
    }
}
