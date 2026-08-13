pub mod pcap;
pub mod writer;

#[cfg(test)]
pub(crate) mod test_util {
    use std::sync::{Mutex, MutexGuard};

    static CWD_LOCK: Mutex<()> = Mutex::new(());

    pub(crate) fn lock_current_dir() -> MutexGuard<'static, ()> {
        CWD_LOCK.lock().expect("cwd test lock poisoned")
    }
}

pub use pcap::*;
pub use writer::*;

pub mod error {
    pub use nettrap_core::error::*;
}

pub mod prelude {
    pub use crate::pcap::*;
    pub use crate::writer::*;
    pub use nettrap_core::error::{Error, Result};
    pub use nettrap_core::prelude::*;
}
