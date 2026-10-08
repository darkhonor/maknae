use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

/// The inode flags `lsattr` reads, from `ioctl(FS_IOC_GETFLAGS)` on the open file.
#[allow(unsafe_code)]
pub(crate) fn inode_flags(file: &File) -> io::Result<libc::c_int> {
    let mut flags: libc::c_int = 0;
    // SAFETY: the descriptor is borrowed from `file`, which is live for the whole call.
    // FS_IOC_GETFLAGS writes one `c_int` through its argument, and the pointer passed is
    // to `flags`, a local `c_int` that outlives the call; nothing else is dereferenced.
    let rc = unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_GETFLAGS, &raw mut flags) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(flags)
}
