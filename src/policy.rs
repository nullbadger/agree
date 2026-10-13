/// Whether an existing share file may be replaced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Overwrite {
    Refuse,
    Replace,
}

impl Overwrite {
    pub(crate) fn from_flag(force: bool) -> Self {
        if force {
            Self::Replace
        } else {
            Self::Refuse
        }
    }
}

/// Whether a blueprint may run shell password providers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShellTrust {
    Denied,
    Trusted,
}

impl ShellTrust {
    pub(crate) fn from_flag(trust: bool) -> Self {
        if trust {
            Self::Trusted
        } else {
            Self::Denied
        }
    }
}

/// Whether encrypted shares may ask the operator for a password.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PromptMode {
    Batch,
    Interactive,
}

impl PromptMode {
    pub(crate) fn from_flag(interactive: bool) -> Self {
        if interactive {
            Self::Interactive
        } else {
            Self::Batch
        }
    }
}
