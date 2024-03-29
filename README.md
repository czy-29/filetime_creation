# filetime_creation

> **Notice**:
>
> Rust 1.75 stabilized [std::fs::File::set_times](https://doc.rust-lang.org/stable/std/fs/struct.File.html#method.set_times) and [FileTimesExt](https://doc.rust-lang.org/stable/std/os/windows/fs/trait.FileTimesExt.html) trait. This means that if you use Rust 1.75 and above, or your library's MSRV allows the use of 1.75 and above, you no longer need to use this crate, and we recommend that you use the standard library directly.
>
> But if you are unable to use Rust 1.75 and above for some reason, then you still need to use this crate as a workaround.

[Documentation](https://docs.rs/filetime_creation)

An enhanced version of [filetime](https://crates.io/crates/filetime), which can set file creation time on Windows.

Internally, this use [SetFileTime](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfiletime)
Win32 API to set the file creation time on Windows.

On other platforms, all functions will just call the corresponding [filetime](https://crates.io/crates/filetime)'s
function, and ignore the file creation time.

```toml
# Cargo.toml
[dependencies]
filetime_creation = "0.1"
```

# License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in filetime_creation by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
