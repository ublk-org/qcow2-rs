extern crate utilities;

#[cfg(not(target_os = "windows"))]
#[cfg(test)]
mod sync_io_integretion {
    use crypto_hash::{hex_digest, Algorithm};
    use qcow2_rs::dev::*;
    use qcow2_rs::utils::*;
    use qcow2_rs::{page_aligned_vec, qcow2_default_params};
    use std::path::PathBuf;
    use tokio::runtime::Runtime;
    use utilities::*;

    async fn calculate_qcow2_data_md5_sync(qcow2f: &tempfile::NamedTempFile, size: u64) -> String {
        let path = PathBuf::from(qcow2f.path());
        let params = qcow2_default_params!(true, false);
        let dev = qcow2_setup_dev_sync(&path, &params).unwrap();

        dev.qcow2_prep_io().await.unwrap();

        let mut buf = page_aligned_vec!(u8, size as usize);
        dev.read_at(&mut buf, 0).await.unwrap();

        hex_digest(Algorithm::MD5, &buf)
    }

    #[test]
    fn test_qcow2_dev_read_sync() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            let size = 2_u64 << 20;
            let cluster_bits = 16;
            let (rawf, qcow2f) = make_rand_qcow2_img(size, cluster_bits);

            let qcow2_sum = calculate_qcow2_data_md5_sync(&qcow2f, size).await;
            let raw_sum = calculate_raw_md5(rawf.path().to_str().unwrap(), 0, size as usize);

            //println!("{} vs. {}", raw_sum, qcow2_sum);
            assert!(raw_sum == qcow2_sum);
        });
    }
}
