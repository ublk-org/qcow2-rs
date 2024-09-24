mod common;

#[cfg(test)]
mod integretion {
    use crate::common::*;
    use crypto_hash::{hex_digest, Algorithm};
    use qcow2_rs::helpers::Qcow2IoBuf;
    use std::io::Read;
    use tokio::runtime::Runtime;

    async fn __test_qcow2_utility_convert(exe_path: String) {
        let size = 8 << 20;
        let cluster_bits = 16;

        let mut buf = Qcow2IoBuf::<u8>::new(size as usize);
        let raw_f = make_rand_raw_img(size, cluster_bits);
        let raw_p = raw_f.path().to_str().unwrap();
        let raw_sum = {
            let mut file = std::fs::File::open(raw_p).unwrap();
            file.read(&mut buf).unwrap();
            hex_digest(Algorithm::MD5, &buf)
        };

        let qcow2_f = tempfile::NamedTempFile::new().unwrap();
        let qcow2_p = qcow2_f.path().to_str().unwrap();
        let raw_f2 = tempfile::NamedTempFile::new().unwrap();
        let raw_p2 = raw_f2.path().to_str().unwrap();

        let para = format!(
            "{} convert -f raw -O qcow2 -o {} {}",
            &exe_path, &qcow2_p, &raw_p
        );
        run_shell_cmd(&para);
        let qcow2_sum = calculate_qcow2_data_md5(&qcow2_f, 0, size).await;
        assert!(raw_sum == qcow2_sum);

        let para = format!(
            "{} convert -f qcow2 -O raw -o {} {}",
            &exe_path, &raw_p2, &qcow2_p
        );
        run_shell_cmd(&para);
        let raw_sum2 = {
            let mut file = std::fs::File::open(raw_p2).unwrap();
            file.read(&mut buf).unwrap();
            hex_digest(Algorithm::MD5, &buf)
        };
        assert!(raw_sum == raw_sum2);
    }

    #[test]
    fn test_qcow2_utility_convert() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            let exe_path = if cfg!(debug_assertions) {
                format!("target/debug/qcow2")
            } else {
                format!("target/release/qcow2")
            };
            __test_qcow2_utility_convert(exe_path).await;
        });
    }
}
