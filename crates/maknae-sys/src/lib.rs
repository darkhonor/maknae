#![cfg(unix)]

mod flags;

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod reply;

mod term;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

pub use flags::is_append_only;
pub use term::window_size;

#[cfg(target_os = "macos")]
pub use macos::full_path;
