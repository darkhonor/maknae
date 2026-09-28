#![cfg(unix)]

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod reply;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::full_path;
