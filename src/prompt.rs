use {
    crate::{error::Error, secret::Password},
    anyhow::{Context, Result},
    std::io::{self, BufRead, IsTerminal, Read, Write},
};

/// Terminal and stdin prompts. Engine code does not read the console itself.
pub(crate) struct Console {
    debug: bool,
}

impl Console {
    pub(crate) fn new(debug: bool) -> Self {
        Self { debug }
    }

    pub(crate) fn reveal(&self, what: &str, value: &str) {
        if self.debug {
            eprintln!("debug: {what} = {value:?} ({} bytes)", value.len());
        }
    }

    pub(crate) fn passwords(&self, labels: &[String], from_stdin: bool) -> Result<Vec<Option<Password>>> {
        if from_stdin {
            return read_password_lines(labels.len());
        }
        if !io::stderr().is_terminal() {
            anyhow::bail!(
                "passwords require a terminal; stdin is reserved for the secret on split and for --password-stdin on \
                 restore"
            );
        }
        let mut passwords = Vec::with_capacity(labels.len());
        for label in labels {
            passwords.push(prompt_password(label)?);
        }
        Ok(passwords)
    }

    pub(crate) fn required_password(&self, label: &str) -> Result<Password> {
        loop {
            let value = hidden_line(&format!("Password for {label}"))?;
            let confirm = hidden_line("Confirm password")?;
            if value != confirm {
                eprintln!("passwords do not match");
                continue;
            }
            return Ok(Password::new(value)?);
        }
    }

    pub(crate) fn pin(&self, from_stdin: bool, label: &str) -> Result<Vec<u8>> {
        let pin = if from_stdin {
            let mut line = String::new();
            io::stdin()
                .lock()
                .read_line(&mut line)
                .with_context(|| format!("Failed to read PIN for {label}"))?;
            trim_line(line)
        } else {
            if !io::stderr().is_terminal() {
                anyhow::bail!("YubiKey PIN requires a terminal, or pass --pin-stdin");
            }
            self.prompt_line(&format!("PIN for {label}"))?
        };
        self.reveal(&format!("PIN for {label}"), &pin);
        if pin.is_empty() || pin.len() > 8 {
            return Err(Error::InvalidPin.into());
        }
        Ok(pin.into_bytes())
    }

    /// One management key for one YubiKey. Empty means the factory default.
    /// Callers validate a non-empty answer; a typo should be re-prompted, not
    /// fatal.
    pub(crate) fn management_key(&self, label: &str) -> Result<Option<String>> {
        if !io::stderr().is_terminal() {
            anyhow::bail!("YubiKey management key requires a terminal, or pass --management-key");
        }
        loop {
            let value = self.prompt_line(&format!(
                "Management key for {label} (48 hex, empty for factory default)"
            ))?;
            self.reveal(&format!("management key for {label}"), &value);
            if value.is_empty() {
                warn_default_management_key(label);
                return Ok(None);
            }
            let confirm = self.prompt_line("Confirm management key")?;
            self.reveal("confirm management key", &confirm);
            if value != confirm {
                eprintln!("management keys do not match");
                continue;
            }
            return Ok(Some(value));
        }
    }

    fn prompt_line(&self, prompt: &str) -> Result<String> {
        prompt_line(prompt, self.debug)
    }
}

fn prompt_password(label: &str) -> Result<Option<Password>> {
    loop {
        let value = hidden_line(&format!("Password for {label} (empty to leave unprotected)"))?;
        if value.is_empty() {
            return Ok(None);
        }
        let confirm = hidden_line("Confirm password")?;
        if value != confirm {
            eprintln!("passwords do not match");
            continue;
        }
        return Ok(Some(Password::new(value)?));
    }
}

/// Read one line from `/dev/tty`. Stdin may be the secret. Debug entry is
/// echoed.
fn hidden_line(prompt: &str) -> Result<String> {
    prompt_line(prompt, false)
}

fn prompt_line(prompt: &str, echo: bool) -> Result<String> {
    write!(io::stderr(), "{prompt}: ").context("Failed to show prompt")?;
    io::stderr().flush().context("Failed to show prompt")?;
    let value = tty::read_line(echo).with_context(|| format!("Failed to read {prompt}"))?;
    if !echo {
        writeln!(io::stderr()).ok();
    }
    Ok(value)
}

fn read_password_lines(count: usize) -> Result<Vec<Option<Password>>> {
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    let mut passwords = Vec::with_capacity(count);
    for index in 1..=count {
        let line = lines
            .next()
            .with_context(|| format!("missing password line for share {index}"))?
            .context("Failed to read password line")?;
        if line.is_empty() {
            passwords.push(None);
        } else {
            passwords.push(Some(Password::new(line)?));
        }
    }
    Ok(passwords)
}

fn trim_line(mut line: String) -> String {
    while line.ends_with(['\n', '\r']) {
        line.pop();
    }
    line
}

pub(crate) fn warn_default_management_key(label: &str) {
    let _ = writeln!(
        io::stderr(),
        "warning: using the factory-default management key for {label}"
    );
}

/// Ask the operator to plug in one key. Reads `/dev/tty`, not stdin, so a piped
/// secret or password file is left intact.
pub(crate) fn wait_for_key(instruction: &str) -> Result<()> {
    eprintln!("{instruction}");
    let mut tty = std::fs::File::open("/dev/tty").context("interactive YubiKey prompt requires a terminal")?;
    let mut byte = [0u8; 1];
    loop {
        let read = tty.read(&mut byte).context("Failed to wait for YubiKey confirmation")?;
        if read == 0 || byte[0] == b'\n' {
            return Ok(());
        }
    }
}

/// Hidden terminal reads. Opens `/dev/tty` read-only: on macOS, opening it
/// read-write while stdin is redirected makes `tcgetattr` return `EBADF`.
mod tty {
    #![allow(unsafe_code)]

    use std::{
        fs::File,
        io::{self, Read},
        os::fd::{AsRawFd, RawFd},
    };

    pub(super) fn read_line(echo: bool) -> io::Result<String> {
        let mut tty = File::open("/dev/tty")?;
        let _restore = if echo {
            None
        } else {
            let fd = tty.as_raw_fd();
            let original = read_termios(fd)?;
            let mut hidden = original;
            hidden.c_lflag &= !libc::ECHO;
            set_termios(fd, libc::TCSAFLUSH, &hidden)?;
            Some(EchoGuard { fd, original })
        };
        let mut bytes = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let read = tty.read(&mut byte)?;
            if read == 0 || byte[0] == b'\n' {
                break;
            }
            if byte[0] != b'\r' {
                bytes.push(byte[0]);
            }
        }
        String::from_utf8(bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
    }

    struct EchoGuard {
        fd: RawFd,
        original: libc::termios,
    }

    impl Drop for EchoGuard {
        fn drop(&mut self) {
            let _ = set_termios(self.fd, libc::TCSANOW, &self.original);
        }
    }

    fn read_termios(fd: RawFd) -> io::Result<libc::termios> {
        // SAFETY: the pointer is a live stack `termios` and is not retained.
        let mut termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut termios) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(termios)
    }

    fn set_termios(fd: RawFd, action: libc::c_int, termios: &libc::termios) -> io::Result<()> {
        // SAFETY: `termios` is a live stack value. `fd` is the open `/dev/tty`.
        if unsafe { libc::tcsetattr(fd, action, termios) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

pub(crate) fn refuse_terminal_stdout() -> Result<()> {
    if io::stdout().is_terminal() {
        return Err(Error::TerminalOutput.into());
    }
    Ok(())
}
