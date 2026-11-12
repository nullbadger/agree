#![allow(unsafe_code)]

//! Process hardening for secret bytes.
//!
//! `mlock` keeps a key off swap. It is required: if the operating system
//! refuses, split and restore stop. Disabling core dumps keeps the key out of
//! a crash report. That call can fail for an unprivileged process; callers
//! warn and continue.

use {
    crate::error::Error,
    zeroize::Zeroize,
};

/// Disable core dumps for this process. Failure is reported by the caller.
#[cfg(unix)]
pub(crate) fn disable_core_dumps() -> bool {
    // SAFETY: `setrlimit` only changes this process's core-dump limit. The
    // pointer is a live stack `rlimit` and is not retained.
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &limit) == 0
    }
}

#[cfg(not(unix))]
pub(crate) fn disable_core_dumps() -> bool {
    false
}

/// The split data key. Length is a multiple of 32. Locked while it lives,
/// cleared on drop.
pub(crate) struct DataKey(Vec<u8>);

impl DataKey {
    pub(crate) fn generate(len: usize) -> Result<Self, Error> {
        let mut bytes = vec![0u8; len];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut bytes);
        match lock(&mut bytes) {
            | Ok(()) => Ok(Self(bytes)),
            | Err(err) => {
                bytes.zeroize();
                Err(err)
            },
        }
    }

    pub(crate) fn from_bytes(mut bytes: Vec<u8>) -> Result<Self, Error> {
        match lock(&mut bytes) {
            | Ok(()) => Ok(Self(bytes)),
            | Err(err) => {
                bytes.zeroize();
                Err(err)
            },
        }
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for DataKey {
    fn drop(&mut self) {
        unlock(&mut self.0);
        self.0.zeroize();
    }
}

impl std::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DataKey(<redacted>)")
    }
}

/// Lock and immediately drop a key of `len` bytes.
///
/// Split and restore call this before prompts and before reading the secret,
/// so a machine that cannot pin the key never touches a token or the secret.
pub(crate) fn require_mlock(len: usize) -> Result<(), Error> {
    let _probe = DataKey::generate(len)?;
    Ok(())
}

fn lock(bytes: &mut [u8]) -> Result<(), Error> {
    if bytes.is_empty() {
        return Err(Error::MlockFailed {
            reason: "empty buffer".into(),
        });
    }
    lock_pages(bytes)
}

#[cfg(unix)]
fn lock_pages(bytes: &mut [u8]) -> Result<(), Error> {
    // SAFETY: `bytes` is a live non-empty mutable slice. `mlock` pins those
    // pages until `munlock`. It does not take ownership of the pointer.
    let rc = unsafe { libc::mlock(bytes.as_ptr().cast::<libc::c_void>(), bytes.len()) };
    if rc == 0 {
        return Ok(());
    }
    Err(Error::MlockFailed {
        reason: std::io::Error::last_os_error().to_string(),
    })
}

#[cfg(not(unix))]
fn lock_pages(bytes: &mut [u8]) -> Result<(), Error> {
    let _ = bytes;
    Err(Error::MlockFailed {
        reason: "not supported on this platform".into(),
    })
}

fn unlock(bytes: &mut [u8]) {
    #[cfg(unix)]
    {
        if bytes.is_empty() {
            return;
        }
        // SAFETY: same allocation passed to `mlock` for this key. Drop cannot
        // report a failure; process exit releases any lock this call misses.
        unsafe {
            let _ = libc::munlock(bytes.as_ptr().cast::<libc::c_void>(), bytes.len());
        }
    }
    #[cfg(not(unix))]
    {
        let _ = bytes;
    }
}

#[cfg(test)]
mod tests {
    use super::DataKey;

    #[test]
    fn refuses_to_lock_an_empty_buffer() {
        let err = DataKey::generate(0).unwrap_err().to_string();
        assert!(err.contains("mlock failed"), "{err}");
        assert!(err.contains("refusing to continue"), "{err}");
    }
}
