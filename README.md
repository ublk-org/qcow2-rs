# qcow2-rs

[![license](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/ming1/qcow2-rs/blob/master/LICENSE-MIT)
[![license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/ming1/qcow2-rs/blob/master/LICENSE-APACHE)

Library in qcow2-rs is for reading/writing data from qcow2 image, and
it supports the following features:

- async/await, support multiple io engines, verified on tokio-uring, raw
linux sync IO syscall and io-uring[^3] with smol[^2] runtime, and direct IO is
allowed with tokio-uring

- basic read/write function on data file, backing file and compressed image

- l2 table & refcount block slice load & store

- block device like interface, minimized read/write unit is aligned with
direct IO minimized block size of the qcow2 image

This project is based on qcow2 implementation from `rsd`[^1]

Motivation of this project is for supporting ublk-qcow2, but turns out it
becomes one generic async qcow2 library.

## Example

```Rust

    tokio_uring::start(async move {
        let params = qcow2_rs::dev::Qcow2DevParams::new(9, None, None, false, true);
        let path = std::path::PathBuf::from("test.qcow2");
        let dev = qcow2_rs::utils::qcow2_setup_dev_uring(&path, &params)
            .await
            .unwrap();

        let mut buf = qcow2_rs::page_aligned_vec!(u8, 4096);

        // read 4096 bytes to `buf` from virt offset 0 of `test.qcow2`
        let _ = dev.read_at(&mut buf, 0).await.unwrap();

        // write 4096 bytes from `buf` to virt offset 4096 of `test.qcow2`
        let _ = dev.write_at(&buf, 4096).await.unwrap();

        // flush meta data lazily, which is done in soft update style
        dev.flush_meta().await.unwrap();
    });

```

## License

This project is licensed under MIT OR Apache.

## Contributing

Any kinds of contributions are welcome!

## References

[^1]: <https://gitlab.com/hreitz/rsd/-/tree/main/src/node/qcow2?ref_type=heads>
[^2]: <https://docs.rs/smol>
[^3]: <https://docs.rs/io-uring>
