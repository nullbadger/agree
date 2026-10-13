use anyhow::{
    bail,
    Result,
};

/// Number of shares a split is allowed to produce.
///
/// Shamir's construction over GF(256) evaluates at x = 1..=255, so 255 is the
/// maximum.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct ShareCount(u8);

impl ShareCount {
    pub(crate) const MAX: usize = 255;

    pub(crate) fn new(value: usize) -> Result<Self> {
        if value == 0 {
            bail!("share count must be greater than 0");
        }
        let Ok(value) = u8::try_from(value) else {
            bail!("share count {value} exceeds {}", Self::MAX);
        };
        Ok(Self(value))
    }

    pub(crate) fn get(self) -> usize {
        usize::from(self.0)
    }
}

/// Minimum number of shares required to restore a secret. Never zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct Threshold(u8);

impl Threshold {
    pub(crate) fn new(value: usize) -> Result<Self> {
        if value == 0 {
            bail!("threshold must be greater than 0");
        }
        let Ok(value) = u8::try_from(value) else {
            bail!("threshold {value} exceeds {}", ShareCount::MAX);
        };
        Ok(Self(value))
    }

    pub(crate) fn get(self) -> u8 {
        self.0
    }

    pub(crate) fn as_usize(self) -> usize {
        usize::from(self.0)
    }
}
