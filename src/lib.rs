//! Timestamps for files in Rust
//!
//! Like [filetime](https://docs.rs/filetime), but can set file creation time.
//!
//! Internally, this crate use [SetFileTime](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfiletime)
//! Win32 API to set the file creation time on Windows.
//!
//! On other platforms, all functions will just call the corresponding [filetime](https://docs.rs/filetime)'s funtion, and
//! ignore the file creation time.
//!
//! # Installation
//!
//! Add this to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! filetime_creation = "0.1"
//! ```
//!
//! # Usage
//!
//! ```no_run
//! use std::fs;
//! use filetime_creation::{FileTime, set_file_ctime};
//!
//! let now = FileTime::now();
//!
//! set_file_ctime("test.txt", now);
//! assert_eq!(now, FileTime::from(fs::metadata("test.txt").unwrap().created().unwrap()));
//! ```

pub use filetime::{set_file_atime, set_file_mtime, FileTime};

use std::fs::{self, OpenOptions};
use std::io;
use std::path::Path;
use std::ptr;

cfg_if::cfg_if! {
    if #[cfg(windows)] {
        use std::os::windows::prelude::*;
        use windows_sys::Win32::Foundation::{FILETIME, HANDLE};
        use windows_sys::Win32::Storage::FileSystem::*;
    }
}

/// Set the last access and modification times for a file on the filesystem.
///
/// This function will set the `atime` and `mtime` metadata fields for a file
/// on the local filesystem, returning any error encountered.
#[cfg(windows)]
pub fn set_file_times<P>(p: P, atime: FileTime, mtime: FileTime, ctime: FileTime) -> io::Result<()>
where
    P: AsRef<Path>,
{
    let f = OpenOptions::new()
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(p)?;
    set_file_handle_times(&f, Some(atime), Some(mtime), Some(ctime))
}

/// Set the last access time for a file on the filesystem.
///
/// This function will set the `atime` metadata field for a file on the local
/// filesystem, returning any error encountered.
///
/// # Platform support
///
/// Where supported this will attempt to issue just one syscall to update only
/// the `atime`, but where not supported this may issue one syscall to learn the
/// existing `mtime` so only the `atime` can be configured.
#[cfg(windows)]
pub fn set_file_ctime<P>(p: P, ctime: FileTime) -> io::Result<()>
where
    P: AsRef<Path>,
{
    let f = OpenOptions::new()
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(p)?;
    set_file_handle_times(&f, None, None, Some(ctime))
}

/// Set the last access and modification times for a file handle.
///
/// This function will either or both of  the `atime` and `mtime` metadata
/// fields for a file handle , returning any error encountered. If `None` is
/// specified then the time won't be updated. If `None` is specified for both
/// options then no action is taken.
#[cfg(windows)]
pub fn set_file_handle_times(
    f: &fs::File,
    atime: Option<FileTime>,
    mtime: Option<FileTime>,
    ctime: Option<FileTime>,
) -> io::Result<()> {
    let atime = atime.map(to_filetime);
    let mtime = mtime.map(to_filetime);
    let ctime = ctime.map(to_filetime);
    return unsafe {
        let ret = SetFileTime(
            f.as_raw_handle() as HANDLE,
            ctime
                .as_ref()
                .map(|p| p as *const FILETIME)
                .unwrap_or(ptr::null()),
            atime
                .as_ref()
                .map(|p| p as *const FILETIME)
                .unwrap_or(ptr::null()),
            mtime
                .as_ref()
                .map(|p| p as *const FILETIME)
                .unwrap_or(ptr::null()),
        );
        if ret != 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    };

    fn to_filetime(ft: FileTime) -> FILETIME {
        let intervals =
            ft.seconds() * (1_000_000_000 / 100) + ((ft.nanoseconds() as i64) / 100);
        FILETIME {
            dwLowDateTime: intervals as u32,
            dwHighDateTime: (intervals >> 32) as u32,
        }
    }
}

/// Set the last access and modification times for a file on the filesystem.
/// This function does not follow symlink.
///
/// This function will set the `atime` and `mtime` metadata fields for a file
/// on the local filesystem, returning any error encountered.
#[cfg(windows)]
pub fn set_symlink_file_times<P>(
    p: P,
    atime: FileTime,
    mtime: FileTime,
    ctime: FileTime,
) -> io::Result<()>
where
    P: AsRef<Path>,
{
    let f = OpenOptions::new()
        .write(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(p)?;
    set_file_handle_times(&f, Some(atime), Some(mtime), Some(ctime))
}

/// Set the last access and modification times for a file on the filesystem.
///
/// This function will set the `atime` and `mtime` metadata fields for a file
/// on the local filesystem, returning any error encountered.
#[cfg(not(windows))]
pub fn set_file_times<P>(p: P, atime: FileTime, mtime: FileTime, _ctime: FileTime) -> io::Result<()>
where
    P: AsRef<Path>,
{
    filetime::set_file_times(p, atime, mtime)
}

/// Set the last access time for a file on the filesystem.
///
/// This function will set the `atime` metadata field for a file on the local
/// filesystem, returning any error encountered.
///
/// # Platform support
///
/// Where supported this will attempt to issue just one syscall to update only
/// the `atime`, but where not supported this may issue one syscall to learn the
/// existing `mtime` so only the `atime` can be configured.
#[cfg(not(windows))]
pub fn set_file_ctime<P>(p: P, _ctime: FileTime) -> io::Result<()>
where
    P: AsRef<Path>,
{
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Platform unsupported",
    ))
}

/// Set the last access and modification times for a file handle.
///
/// This function will either or both of  the `atime` and `mtime` metadata
/// fields for a file handle , returning any error encountered. If `None` is
/// specified then the time won't be updated. If `None` is specified for both
/// options then no action is taken.
#[cfg(not(windows))]
pub fn set_file_handle_times(
    f: &fs::File,
    atime: Option<FileTime>,
    mtime: Option<FileTime>,
    _ctime: Option<FileTime>,
) -> io::Result<()> {
    filetime::set_file_handle_times(f, atime, mtime)
}

/// Set the last access and modification times for a file on the filesystem.
/// This function does not follow symlink.
///
/// This function will set the `atime` and `mtime` metadata fields for a file
/// on the local filesystem, returning any error encountered.
#[cfg(not(windows))]
pub fn set_symlink_file_times<P>(
    p: P,
    atime: FileTime,
    mtime: FileTime,
    _ctime: FileTime,
) -> io::Result<()>
where
    P: AsRef<Path>,
{
    filetime::set_symlink_file_times(p, atime, mtime)
}

#[cfg(test)]
mod tests {}
