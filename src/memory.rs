#![allow(unsafe_code)]

//! Best-effort process hardening for secret bytes.
//!
//! `mlock` keeps a key off swap. Disabling core dumps keeps it out of a crash
//! report. Both can fail for an unprivileged process; callers warn and continue
//! so a container can still run the ceremony.

use zeroize::Zeroize;

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
    pub(crate) fn generate(len: usize) -> Self {
        let mut bytes = vec![0u8; len];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut bytes);
        lock(&mut bytes);
        Self(bytes)
    }

    pub(crate) fn from_bytes(mut bytes: Vec<u8>) -> Self {
        lock(&mut bytes);
        Self(bytes)
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

fn lock(bytes: &mut [u8]) {
    #[cfg(unix)]
    {
        // SAFETY: `bytes` is a live mutable slice. `mlock` pins those pages
        // until `munlock`. It does not take ownership of the pointer.
        unsafe {
            let _ = libc::mlock(bytes.as_ptr().cast::<libc::c_void>(), bytes.len());
        }
    }
    #[cfg(not(unix))]
    {
        let _ = bytes;
    }
}

fn unlock(bytes: &mut [u8]) {
    #[cfg(unix)]
    {
        // SAFETY: same allocation passed to `mlock` for this key.
        unsafe {
            let _ = libc::munlock(bytes.as_ptr().cast::<libc::c_void>(), bytes.len());
        }
    }
    #[cfg(not(unix))]
    {
        let _ = bytes;
    }
}
