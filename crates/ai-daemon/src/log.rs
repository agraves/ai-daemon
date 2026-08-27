// SPDX-License-Identifier: Apache-2.0

//! Logging, such as it is.
//!
//! systemd captures stderr, and `sd-daemon`'s `<N>` prefix is how a plain
//! `write(2)` tells journald a priority. That is the whole mechanism — a
//! logging crate here would buy configurability nobody wants from a system
//! service whose log destination is decided by its unit file.
//!
//! The one rule that matters: **no prompt or completion content is ever
//! written here** (§5). Identities, model names, byte counts and token counts
//! are the vocabulary; the text is not.

use std::fmt;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

static DEBUG: AtomicBool = AtomicBool::new(false);

pub fn set_debug(on: bool) {
    DEBUG.store(on, Ordering::Relaxed);
}

pub fn debug_enabled() -> bool {
    DEBUG.load(Ordering::Relaxed)
}

pub fn emit(priority: u8, args: fmt::Arguments<'_>) {
    let mut err = std::io::stderr().lock();
    let _ = writeln!(err, "<{priority}>{args}");
    let _ = err.flush();
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => { $crate::log::emit(3, format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => { $crate::log::emit(4, format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => { $crate::log::emit(6, format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        if $crate::log::debug_enabled() {
            $crate::log::emit(7, format_args!($($arg)*))
        }
    };
}
