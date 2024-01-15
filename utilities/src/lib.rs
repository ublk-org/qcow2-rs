use crypto_hash::{hex_digest, Algorithm};
use qcow2_rs::dev::{Qcow2Dev, Qcow2DevParams};
use qcow2_rs::meta::Qcow2Header;
use qcow2_rs::ops::Qcow2IoOps;
use qcow2_rs::utils::qcow2_setup_dev_tokio;
use qcow2_rs::{page_aligned_vec, qcow2_default_params};
use rand::Rng;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::process::Command;
use std::rc::Rc;

pub fn run_shell_cmd(p: &str) {
    //println!("Run shell command {}", p);
    let pp = p.to_string();
    let tokens: Vec<&str> = pp.split(' ').collect();
    let output = Command::new(&tokens[0])
        .args(&tokens[1..])
        .output()
        .expect("Failed to execute process");

    if !output.status.success() {
        // Print error message if the command failed
        let error = String::from_utf8_lossy(&output.stderr);
        eprintln!("Command failed with error:\n{}", error);
        panic!();
    }
}

fn make_qcow2_buf(cluster_bits: usize, refcount_order: u8, size: u64) -> Vec<u8> {
    let bs_shift = 9_u8;
    let bs = 1 << bs_shift;
    let (rc_t, rc_b, _) =
        Qcow2Header::calculate_meta_params(size, cluster_bits, refcount_order, bs);
    let clusters = 1 + rc_t.1 + rc_b.1;
    let img_size = ((clusters as usize) << cluster_bits) + 512;
    let mut buf = vec![0u8; img_size];

    Qcow2Header::format_qcow2(&mut buf, size, cluster_bits, refcount_order, bs).unwrap();

    buf
}

pub fn make_temp_qcow2_img(
    size: u64,
    cluster_bits: usize,
    refcount_order: u8,
) -> tempfile::NamedTempFile {
    let tmpfile = tempfile::NamedTempFile::new().unwrap();
    let mut file = std::fs::File::create(tmpfile.path()).unwrap();

    let buf = make_qcow2_buf(cluster_bits, refcount_order, size);
    file.write_all(&buf).unwrap();

    tmpfile
}

pub fn calculate_raw_md5(file_path: &str, off: u64, len: usize) -> String {
    let mut file = std::fs::File::open(file_path).unwrap();
    let mut buffer = vec![0_u8; len];

    file.seek(SeekFrom::Start(off)).unwrap();
    file.read(&mut buffer).unwrap();

    hex_digest(Algorithm::MD5, &buffer)
}

pub fn make_rand_raw_img(size: u64, cls_bits: usize) -> tempfile::NamedTempFile {
    let tmp_inp = tempfile::NamedTempFile::new().unwrap();
    let buf_len = 10 << cls_bits;
    let mut buf = vec![0_u8; buf_len];

    let mut file = std::fs::File::create(tmp_inp.path()).unwrap();
    for off in (0..size).step_by(buf_len) {
        let mut rng = rand::thread_rng();
        rng.fill(&mut buf[..]);
        file.seek(SeekFrom::Start(off)).unwrap();
        file.write(&buf).unwrap();
    }

    tmp_inp
}

pub fn make_rand_qcow2_img(
    size: u64,
    cluster_bits: usize,
) -> (tempfile::NamedTempFile, tempfile::NamedTempFile) {
    let tmp_inp = make_rand_raw_img(size, cluster_bits);
    let tmp_outp = tempfile::NamedTempFile::new().unwrap();
    let in_path = tmp_inp.path().to_str().unwrap();
    let out_path = tmp_outp.path().to_str().unwrap();

    let para = format!(
        "qemu-img convert -f raw -O qcow2 {} {}",
        &in_path, &out_path
    );
    run_shell_cmd(&para);

    (tmp_inp, tmp_outp)
}

pub fn make_compressed_qcow2_img(
    size: u64,
    _cluster_bits: usize,
) -> (tempfile::NamedTempFile, tempfile::NamedTempFile) {
    let tmp_inp = tempfile::NamedTempFile::new().unwrap();
    let tmp_outp = tempfile::NamedTempFile::new().unwrap();
    let in_path = tmp_inp.path().to_str().unwrap();
    let out_path = tmp_outp.path().to_str().unwrap();

    let buf_len = 1 << 20;
    let binding = std::env::current_exe().unwrap();
    {
        let mut file = std::fs::File::open(&binding).unwrap();
        let mut buf = vec![0_u8; buf_len];
        file.read(&mut buf).unwrap();

        let mut file = std::fs::File::create(tmp_inp.path()).unwrap();
        for off in (0..size).step_by(buf_len) {
            file.seek(SeekFrom::Start(off)).unwrap();
            file.write(&buf).unwrap();
        }
    }

    let para = format!(
        "qemu-img convert -c -f raw -O qcow2 {} {}",
        &in_path, &out_path
    );
    run_shell_cmd(&para);

    //let para = format!("cp -f {} {}", &in_path, "tt.raw");
    //run_shell_cmd(&para);
    //let para = format!("cp -f {} {}", &out_path, "tt.qcow2");
    //run_shell_cmd(&para);

    (tmp_inp, tmp_outp)
}

pub fn make_backing_qcow2_img(backing: &tempfile::NamedTempFile) -> tempfile::NamedTempFile {
    let tmp_outp = tempfile::NamedTempFile::new().unwrap();
    let out_path = tmp_outp.path().to_str().unwrap();
    let in_path = backing.path().to_str().unwrap();

    let cmd = format!(
        "qemu-img create -f qcow2 -F qcow2 -b {} {}",
        &in_path, out_path
    );
    run_shell_cmd(&cmd);

    tmp_outp
}

//so far only support 2 level backing device
pub async fn calculate_qcow2_data_md5(
    qcow2f: &tempfile::NamedTempFile,
    off: u64,
    size: u64,
) -> String {
    let path = PathBuf::from(qcow2f.path());
    let params = qcow2_default_params!(true, false);
    let dev = qcow2_setup_dev_tokio(&path, &params).await.unwrap();

    let mut buf = page_aligned_vec!(u8, size as usize);
    dev.read_at(&mut buf, off).await.unwrap();

    hex_digest(Algorithm::MD5, &buf)
}

pub async fn test_qcow2_dev_write_verify<T: Qcow2IoOps + 'static>(
    dev_rc: &Rc<Qcow2Dev<T>>,
    input: Vec<(u64, usize)>,
) {
    let dev = dev_rc.clone();
    let mut fv = Vec::new();
    let local = tokio::task::LocalSet::new();

    for (off, len) in input {
        let d = dev.clone();
        fv.push(local.spawn_local(async move {
            let mut wbuf = page_aligned_vec!(u8, len as usize);

            let mut rng = rand::thread_rng();
            rng.fill(&mut wbuf[..]);

            println!("write at {:x}/{}..", off, len);
            d.write_at(&wbuf, off).await.unwrap();
            println!("write at {:x}/{}..done", off, len);

            let mut rbuf = page_aligned_vec!(u8, len as usize);
            d.read_at(&mut rbuf, off).await.unwrap();

            let w_sum = hex_digest(Algorithm::MD5, &wbuf);
            let r_sum = hex_digest(Algorithm::MD5, &rbuf);

            assert!(w_sum == r_sum);
        }));
    }
    local.await;
    futures::future::join_all(fv).await;

    if dev.need_flush_meta() {
        dev.flush_meta().await.unwrap();
    }
    dev.check().await.unwrap();
}

pub async fn test_cow_write(
    rawf: &tempfile::NamedTempFile,
    qcow2_img: &tempfile::NamedTempFile,
    cluster_bits: usize,
) {
    let path = PathBuf::from(qcow2_img.path());
    let params = qcow2_default_params!(false, false);
    let dev = qcow2_setup_dev_tokio(&path, &params).await.unwrap();

    // we are top device, can't be backing file
    assert!(!dev.info.is_back_file());
    dev.check().await.unwrap();

    // copy two clusters and start 1/2 of the 1st one, so both half
    // and whole cluster are covered
    let size = dev.info.virtual_size();
    let buf_size = 2 << cluster_bits;
    let off = (buf_size / 4) as u64;
    let mut buf = page_aligned_vec!(u8, buf_size);
    let mut rng = rand::thread_rng();
    rng.fill(&mut buf[..]);
    let buf_md5 = hex_digest(Algorithm::MD5, &buf);
    dev.write_at(&mut buf, off).await.unwrap();
    dev.flush_meta().await.unwrap();
    dev.check().await.unwrap();

    //check if written data is correct
    let qcow2_sum = calculate_qcow2_data_md5(&qcow2_img, off, buf_size as u64).await;
    assert!(qcow2_sum == buf_md5);

    //check if the beginning data is read correctly
    let raw_sum = calculate_raw_md5(rawf.path().to_str().unwrap(), 0, off as usize);
    let qcow2_sum = calculate_qcow2_data_md5(&qcow2_img, 0, off).await;
    assert!(qcow2_sum == raw_sum);

    //check if the tail data is read correctly
    let right_off = off + (buf_size as u64);
    let raw_sum = calculate_raw_md5(
        rawf.path().to_str().unwrap(),
        right_off,
        (size - right_off).try_into().unwrap(),
    );
    let qcow2_sum = calculate_qcow2_data_md5(
        &qcow2_img,
        right_off,
        (size - right_off).try_into().unwrap(),
    )
    .await;
    assert!(qcow2_sum == raw_sum);
}
