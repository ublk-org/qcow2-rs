mod common;

#[cfg(test)]
mod integretion {
    use crate::common::*;
    use crypto_hash::{hex_digest, Algorithm};
    use qcow2_rs::dev::*;
    use qcow2_rs::helpers::Qcow2IoBuf;
    use qcow2_rs::qcow2_default_params;
    use qcow2_rs::utils::*;
    use rand::Rng;
    use std::io::Read;
    use std::path::PathBuf;
    use std::time::Instant;
    use tokio::runtime::Runtime;

    #[test]
    fn test_qcow2_dev_read_null() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            let size = 64_u64 << 20;
            let cluster_bits = 16;
            let img_file = make_temp_qcow2_img(size, cluster_bits, 4);
            let path = PathBuf::from(img_file.path());
            let params = qcow2_default_params!(true, false);
            let dev = qcow2_setup_dev_tokio(&path, &params).await.unwrap();

            let mut buf = Qcow2IoBuf::<u8>::new(1 << cluster_bits);
            dev.read_at(&mut buf, 0).await.unwrap();
        });
    }

    #[test]
    fn test_qcow2_dev_read_data() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            let size = 2_u64 << 20;
            let cluster_bits = 16;
            let (rawf, qcow2f) = make_rand_qcow2_img(size, cluster_bits);

            let qcow2_sum = calculate_qcow2_data_md5(&qcow2f, 0, size).await;
            let raw_sum = calculate_raw_md5(rawf.path().to_str().unwrap(), 0, size as usize);

            //println!("{} vs. {}", raw_sum, qcow2_sum);
            assert!(raw_sum == qcow2_sum);
        });
    }

    #[test]
    fn test_qcow2_dev_backing_read() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            let size = 4_u64 << 20;
            let cluster_bits = 16;
            let (rawf, qcow2f) = make_compressed_qcow2_img(size, cluster_bits);
            let qcow2_img = make_backing_qcow2_img(&qcow2f);

            let qcow2_sum = calculate_qcow2_data_md5(&qcow2_img, 0, size).await;
            let raw_sum = calculate_raw_md5(rawf.path().to_str().unwrap(), 0, size as usize);

            //println!("{} vs. {}", raw_sum, qcow2_sum);
            assert!(raw_sum == qcow2_sum);
        });
    }

    #[test]
    fn test_qcow2_dev_read_compressed_data() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            let size = 4_u64 << 20;
            let cluster_bits = 16;
            let (rawf, qcow2f) = make_compressed_qcow2_img(size, cluster_bits);

            let qcow2_sum = calculate_qcow2_data_md5(&qcow2f, 0, size).await;
            let raw_sum = calculate_raw_md5(rawf.path().to_str().unwrap(), 0, size as usize);

            //println!("{} vs. {}", raw_sum, qcow2_sum);
            assert!(raw_sum == qcow2_sum);
        });
    }

    #[test]
    fn test_qcow2_dev_write_compressed_data() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            let size = 4_u64 << 20;
            let cluster_bits = 16;
            let (rawf, qcow2f) = make_compressed_qcow2_img(size, cluster_bits);

            test_cow_write(&rawf, &qcow2f, cluster_bits).await;
        });
    }

    #[test]
    fn test_qcow2_dev_backing_write() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            let size = 16_u64 << 20;
            let cluster_bits = 16;
            let (rawf, qcow2f) = make_compressed_qcow2_img(size, cluster_bits);
            let qcow2_img = make_backing_qcow2_img(&qcow2f);

            test_cow_write(&rawf, &qcow2_img, cluster_bits).await;
        });
    }
    #[test]
    fn test_qcow2_dev_partial_writes_on_cluster_compressed() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            let size = 4_u64 << 20;
            let cluster_bits = 16;
            let (_, qcow2f) = make_compressed_qcow2_img(size, cluster_bits);
            let path = PathBuf::from(qcow2f.path());
            let params = qcow2_default_params!(false, false);

            let dev = std::rc::Rc::new(qcow2_setup_dev_tokio(&path, &params).await.unwrap());
            // we are top device, can't be backing file
            assert!(!dev.info.is_back_file());
            dev.check().await.unwrap();

            let input = vec![(0x108000, 8192), (0x10b000, 4096)];
            test_qcow2_dev_write_verify(&dev, input).await;
        });
    }

    #[test]
    fn test_qcow2_dev_write_partial_cluster() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            let size = 128_u64 << 20;
            let cluster_bits = 16;
            let img_file = make_temp_qcow2_img(size, cluster_bits, 4);
            let path = PathBuf::from(img_file.path());
            let params = qcow2_default_params!(false, false);
            let mut buf = Qcow2IoBuf::<u8>::new(size as usize);
            let mut buf2 = Qcow2IoBuf::<u8>::new(size as usize);
            let bsize = size as usize;
            let boff = 8192;

            let raw_f = make_rand_raw_img(size, cluster_bits);
            let raw_path = raw_f.path().to_str().unwrap();
            let mut file = std::fs::File::open(raw_path).unwrap();
            file.read(&mut buf).unwrap();

            // fill the last 8k as zero
            for i in (bsize - boff)..bsize {
                buf[i] = 0;
            }

            let dev = qcow2_setup_dev_tokio(&path, &params).await.unwrap();
            //the last 8k should be read as zero
            dev.write_at(&buf[..(bsize - boff)], 0).await.unwrap();
            if dev.need_flush_meta() {
                dev.flush_meta().await.unwrap();
            }
            dev.check().await.unwrap();

            let dev2 = qcow2_setup_dev_tokio(&path, &params).await.unwrap();
            dev2.read_at(&mut buf2[..], 0).await.unwrap();

            let raw_sum = hex_digest(Algorithm::MD5, &buf);
            let qcow2_sum = hex_digest(Algorithm::MD5, &buf2);

            if raw_sum != qcow2_sum {
                println!("{} {}", raw_sum, qcow2_sum);
                for i in 0..(size as usize) {
                    if buf[i] != buf2[i] {
                        println!("mismatched in {}", i);
                        println!("correct : {:?}", buf[i..i + 32].to_vec());
                        println!("wrong : {:?}", buf2[i..i + 32].to_vec());
                        break;
                    }
                }
            }

            assert!(qcow2_sum == raw_sum);
        });
    }

    #[test]
    fn test_qcow2_dev_concurrent_writes() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            let size = 256_u64 << 20;
            let cluster_bits = 16;
            let img_file = make_temp_qcow2_img(size, cluster_bits, 4);
            let path = PathBuf::from(img_file.path());
            let params = qcow2_default_params!(false, false);
            let bsize = 512_u64 << 10;

            // build data source from /dev/random
            let mut buf = Qcow2IoBuf::<u8>::new(bsize as usize);
            let raw_f = make_rand_raw_img(bsize, cluster_bits);
            let raw_path = raw_f.path().to_str().unwrap();
            let mut file = std::fs::File::open(raw_path).unwrap();
            file.read(&mut buf).unwrap();
            let raw_sum = hex_digest(Algorithm::MD5, &buf);

            let dev = qcow2_setup_dev_tokio(&path, &params).await.unwrap();
            let mut f_vec = Vec::new();

            let start = Instant::now();
            //write concurrently
            for off in (0..size).step_by(bsize as usize) {
                f_vec.push(dev.write_at(&buf, off as u64));
            }
            futures::future::join_all(f_vec).await;
            let duration = start.elapsed();
            println!(
                "test_qcow2_dev_concurrent_writes: write {} MB in {}ms",
                size >> 20,
                duration.as_millis()
            );

            let start = Instant::now();
            dev.flush_meta().await.unwrap();
            dev.check().await.unwrap();

            let duration = start.elapsed();
            println!(
                "test_qcow2_dev_concurrent_writes: flushing meta for write {} MB in {}us",
                size >> 20,
                duration.as_micros()
            );

            let mut duration = std::time::Duration::new(0, 0);
            //read & checksum
            let rsize = 128_usize << 20;
            assert!(size % (rsize as u64) == 0);

            for off in (0..size).step_by(rsize) {
                let start = Instant::now();
                let mut buf = Qcow2IoBuf::<u8>::new(rsize);
                let r = dev.read_at(&mut buf, off).await.unwrap();
                assert!(r == buf.len());
                duration += start.elapsed();

                for off2 in (0..rsize).step_by(bsize as usize) {
                    assert!(
                        hex_digest(Algorithm::MD5, &buf[off2..(off2 + (bsize as usize))])
                            == raw_sum
                    );
                }
            }
            println!(
                "test_qcow2_dev_concurrent_writes: read {} MB in {}ms",
                size >> 20,
                duration.as_millis()
            );
        });
    }

    #[test]
    fn test_qcow2_dev_concurrent_rw() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            let size = 128_u64 << 20;
            let cluster_bits = 16;
            let img_file = make_temp_qcow2_img(size, cluster_bits, 4);
            let path = PathBuf::from(img_file.path());
            let params = qcow2_default_params!(false, false);

            // build data source from /dev/random
            let mut buf = Qcow2IoBuf::<u8>::new(size as usize);
            let raw_f = make_rand_raw_img(size, cluster_bits);
            let raw_path = raw_f.path().to_str().unwrap();
            let mut file = std::fs::File::open(raw_path).unwrap();
            file.read(&mut buf).unwrap();

            let dev = qcow2_setup_dev_tokio(&path, &params).await.unwrap();

            let write = dev.write_at(&buf, 0);
            let mut rbuf = Qcow2IoBuf::<u8>::new(size as usize);
            let read = dev.read_at(&mut rbuf, 0);

            //run write and read concurrently
            let (res0, res1) = futures::join!(write, read);

            if dev.need_flush_meta() {
                dev.flush_meta().await.unwrap();
            }
            dev.check().await.unwrap();

            assert!(!res0.is_err() && !res1.is_err());
        });
    }

    #[test]
    fn test_qcow2_dev_partial_writes_on_cluster() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            let size = 16_u64 << 20;
            let cluster_bits = 16;
            let img_file = make_temp_qcow2_img(size, cluster_bits, 4);
            let path = PathBuf::from(img_file.path());
            let params = qcow2_default_params!(false, false);

            let dev = std::rc::Rc::new(qcow2_setup_dev_tokio(&path, &params).await.unwrap());
            let input = vec![(0x108000, 8192), (0x10b000, 4096)];
            test_qcow2_dev_write_verify(&dev, input).await;
        });
    }

    #[test]
    fn test_qcow2_dev_partial_writes_on_cluster_backing() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            let size = 16_u64 << 20;
            let cluster_bits = 16;
            let (_, qcow2f) = make_compressed_qcow2_img(size, cluster_bits);
            let qcow2_img = make_backing_qcow2_img(&qcow2f);
            let path = PathBuf::from(qcow2_img.path());
            let params = qcow2_default_params!(false, false);

            let dev = std::rc::Rc::new(qcow2_setup_dev_tokio(&path, &params).await.unwrap());
            // we are top device, can't be backing file
            assert!(!dev.info.is_back_file());

            let input = vec![(0x108000, 8192), (0x10b000, 4096)];
            test_qcow2_dev_write_verify(&dev, input).await;
        });
    }

    #[test]
    fn test_qcow2_dev_random_rw() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            let size = 256_u64 << 20;
            let cluster_bits = 16;
            let img_file = make_temp_qcow2_img(size, cluster_bits, 4);
            let path = PathBuf::from(img_file.path());
            let params = qcow2_default_params!(false, false);
            let dev = std::sync::Arc::new(qcow2_setup_dev_tokio(&path, &params).await.unwrap());
            let mut fv = Vec::new();
            let blocks = size >> params.get_bs_bits();
            let bs = 1 << params.get_bs_bits();
            let min_bs = 1;
            let max_bs = 1024;
            let io_jobs = 32;
            let local = tokio::task::LocalSet::new();

            for _ in 0..io_jobs {
                let d = dev.clone();
                fv.push(local.spawn_local(async move {
                    let mut rng = rand::thread_rng();

                    let off = rng.gen_range(0..blocks) * bs;
                    let bsize = rng.gen_range(min_bs..=max_bs) * bs;
                    let mut wbuf = Qcow2IoBuf::<u8>::new(bsize as usize);
                    rng.fill(&mut wbuf[..]);

                    println!("randwrite: off {:x} len {}", off, bsize);
                    d.write_at(&wbuf, off).await.unwrap();
                }));
            }

            for _ in 0..io_jobs {
                let d = dev.clone();
                fv.push(local.spawn_local(async move {
                    let mut rng = rand::thread_rng();

                    let off = rng.gen_range(0..blocks) * bs;
                    let bsize = rng.gen_range(min_bs..=max_bs) * bs;
                    let mut rbuf = Qcow2IoBuf::<u8>::new(bsize as usize);

                    println!("randread: off {:x} len {}", off, bsize);
                    d.read_at(&mut rbuf, off).await.unwrap();
                }));
            }
            local.await;
            futures::future::join_all(fv).await;

            if dev.need_flush_meta() {
                dev.flush_meta().await.unwrap();
            }

            dev.check().await.unwrap();
        });
    }

    #[test]
    fn test_qcow2_dev_resized_backing_rw() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            let size = 16_u64 << 20;
            let cluster_bits = 16;
            let (_, qcow2f) = make_compressed_qcow2_img(size, cluster_bits);
            let qcow2_img = make_backing_qcow2_img(&qcow2f);
            let path_str = qcow2_img.path().to_str().unwrap();

            let extra = 16_u64 << 20;
            let para = format!("qemu-img resize {} +{}", &path_str, extra);
            run_shell_cmd(&para);

            // read from resized device backing by external image
            let new_len = size + extra;
            calculate_qcow2_data_md5(&qcow2_img, 0, new_len).await;

            // write over resized device backing by external image
            let buf_len = 4 << cluster_bits;
            let mut rng = rand::thread_rng();
            let mut wbuf = Qcow2IoBuf::<u8>::new(buf_len);
            rng.fill(&mut wbuf[..]);
            let off = (1 << cluster_bits) / 2; //cross cluster write
            let wbuf_md5 = hex_digest(Algorithm::MD5, &wbuf);

            let path = PathBuf::from(qcow2_img.path());
            let params = qcow2_default_params!(false, false);
            let dev = qcow2_setup_dev_tokio(&path, &params).await.unwrap();

            dev.write_at(&wbuf, off as u64).await.unwrap();
            let mut rbuf = Qcow2IoBuf::<u8>::new(buf_len);
            dev.read_at(&mut rbuf, off as u64).await.unwrap();
            let rbuf_md5 = hex_digest(Algorithm::MD5, &rbuf);

            dev.flush_meta().await.unwrap();
            dev.check().await.unwrap();

            assert!(wbuf_md5 == rbuf_md5);
        });
    }

    #[test]
    fn test_qcow2_dev_shrink_cache() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            let size = 8_u64 << 20;
            let cluster_bits = 16;
            let img_file = make_temp_qcow2_img(size, cluster_bits, 4);
            let path = PathBuf::from(img_file.path());
            let params = qcow2_default_params!(false, false);
            let dev = std::rc::Rc::new(qcow2_setup_dev_tokio(&path, &params).await.unwrap());

            let input = vec![(0x0, 8192)];
            test_qcow2_dev_write_verify(&dev, input).await;
            assert!(!dev.refblock_cache_is_empty() && !dev.l2_cache_is_empty());
            dev.shrink_caches().await.unwrap();
            assert!(dev.refblock_cache_is_empty() && dev.l2_cache_is_empty());

            let input = vec![(4 << 20, 8192)];
            test_qcow2_dev_write_verify(&dev, input).await;
            assert!(!dev.refblock_cache_is_empty() && !dev.l2_cache_is_empty());
            dev.shrink_caches().await.unwrap();
            assert!(dev.refblock_cache_is_empty() && dev.l2_cache_is_empty());

            dev.check().await.unwrap();
        });
    }
}
