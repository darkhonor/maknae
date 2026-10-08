#![cfg(unix)]

mod flags;

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod reply;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

pub use flags::is_append_only;

#[cfg(target_os = "macos")]
pub use macos::full_path;
