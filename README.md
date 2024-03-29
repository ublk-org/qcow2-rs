# qcow2-rs

[![license](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/ming1/qcow2-rs/blob/master/LICENSE-MIT)
[![license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/ming1/qcow2-rs/blob/master/LICENSE-APACHE)

Library in qcow2-rs is for reading/writing data from qcow2 image, and
follows its features:

- async/await, support multiple io engines, verified on tokio-uring, raw
linux sync IO syscall, tokio and io-uring[^3] with smol[^2] runtime

- support both direct IO and buffered IO, for direct IO, it needs async
runtime support, such as tokio doesn't allow it.

- basic read/write function on data file, backing file and compressed image

- l2 table & refcount block load & store in slice way, and the minimized
slice size is block size, and the maximized size is cluster size

- block device like interface, minimized read/write unit is aligned with
block size of the FS qcow2 image

- cross-platform support, verified on linux(Fedora/ubuntu), freebsd and windows

This project is based on qcow2 implementation from `rsd`[^1]

Motivation of this project is for supporting ublk-qcow2[^4], but turns out it
becomes one generic async qcow2 library. Attributed to Rust async/.await,
the lib is well designed & implemented, and easy to extend(add new features,
improve, ...)

One utility is included in this project, which can dump qcow2 meta,
show any meta related statistics of the image, check image meta integrity &
host cluster leak, format qcow2 image and convert between qcow2 and raw.

## Example

```Rust

    use qcow2_rs::qcow2_default_params;
    use qcow2_rs::utils::qcow2_setup_dev_uring;
    use qcow2_rs::helpers::Qcow2IoBuf;

    tokio_uring::start(async move {
        let params = Qcow2DevParams::new(9, None, None, false, false);
        let path = std::path::PathBuf::from("test.qcow2");

        // setup one qcow2 device
        let dev = qcow2_setup_dev_uring(&path, &params).await.unwrap();

        // create one slice like & aligned IO buffer
        let mut buf = Qcow2IoBuf::<u8>::new(4096);

        // read 4096 bytes to `buf` from virt offset 0 of `test.qcow2`
        let _ = dev.read_at(&mut buf, 0).await.unwrap();

        // write 4096 bytes from `buf` to virt offset 4096 of `test.qcow2`
        let _ = dev.write_at(&buf, 4096).await.unwrap();

        // flush meta data lazily, which is done in soft update style
        dev.flush_meta().await.unwrap();
    });

```

## Test

- for running the built-in test, `qemu-img` is required, so package of
`qemu-utils`(Debian/Ubuntu) or `qemu-img`(Fedora, RHEL, ...) needs to
be installed

- built CI covers 'carget test' on both ubuntu and windows


## License

This project is licensed under MIT OR Apache.

## Contributing

Any kinds of contributions are welcome!

## References

[^1]: <https://gitlab.com/hreitz/rsd/-/tree/main/src/node/qcow2?ref_type=heads>
[^2]: <https://docs.rs/smol>
[^3]: <https://docs.rs/io-uring>
[^4]: <https://github.com/ming1/rublk/tree/qcow2>
