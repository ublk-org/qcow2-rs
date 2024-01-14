extern crate utilities;

#[cfg(test)]
mod uring_integretion {
    use qcow2_rs::dev::*;
    use qcow2_rs::qcow2_default_params;
    use qcow2_rs::utils::*;
    use std::path::PathBuf;
    use utilities::*;

    #[test]
    fn test_qcow2_dev_write_uring() {
        tokio_uring::start(async move {
            let size = 4_u64 << 20;
            let cluster_bits = 16;
            let qcow2f = make_temp_qcow2_img(size, cluster_bits, 4);
            let path = PathBuf::from(qcow2f.path());
            let params = qcow2_default_params!(false, true);

            let dev = std::rc::Rc::new(qcow2_setup_dev_uring(&path, &params).await.unwrap());
            // we are top device, can't be backing file
            assert!(!dev.info.is_back_file());
            dev.check().await.unwrap();

            let input = vec![(0x108000, 8192), (0x10b000, 4096)];
            test_qcow2_dev_write_verify(&dev, input).await;
        });
    }
}
