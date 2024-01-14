use crypto_hash::{hex_digest, Algorithm};
use qcow2_rs::meta::Qcow2Header;
use rand::Rng;
use std::io::{Read, Seek, SeekFrom, Write};
use std::process::Command;

pub fn run_shell_cmd(p: &str) {
    //println!("Run shell command {}", p);
    let tokens = shlex::split(p).unwrap();
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
