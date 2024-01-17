use clap::{Args, Parser, Subcommand};
use clap_num::maybe_hex;
use qcow2_rs::dev::{Qcow2DevParams, Qcow2Info};
use qcow2_rs::error::Qcow2Result;
use qcow2_rs::meta::{
    L1Table, L2Table, Qcow2FeatureType, Qcow2Header, RefBlock, RefTable, Table, TableEntry,
};
use qcow2_rs::utils::qcow2_setup_dev_tokio;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use tokio::runtime::Runtime;

#[derive(Args, Debug)]
pub struct CheckArgs {
    /// qcow2 image path
    file: PathBuf,
}

#[derive(Args, Debug)]
pub struct InfoArgs {
    /// qcow2 image path
    file: PathBuf,

    /// verbose
    #[clap(long, short, default_value_t = false)]
    verbose: bool,
}

#[derive(Args, Debug)]
pub struct MapArgs {
    /// virtual address
    #[clap(short, long, value_parser=maybe_hex::<u64>)]
    addr: u64,

    /// map length, how many clusters
    #[clap(short, long, default_value_t = 1)]
    len: usize,

    /// qcow2 image path
    file: PathBuf,
}

#[derive(Args, Debug)]
pub struct FormatArgs {
    /// virtual size, unit is MB
    #[clap(long, short = 's', default_value_t = 64)]
    size: u32,

    /// Cluster bits, cluster size is 1 << cluster_bits
    #[clap(long, short = 'c', default_value_t = 16)]
    cluster_bits: usize,

    /// refcount order, entry size in refcount table is
    /// 1 << refcount_order
    #[clap(long, short = 'r', default_value_t = 4)]
    refcount_order: u8,

    /// qcow2 image path
    file: PathBuf,
}

#[derive(Args, Debug)]
pub struct DumpArgs {
    /// don't dump qcow2 header
    #[clap(long, short = 'n', default_value_t = false)]
    no_header: bool,

    /// dump refcount table
    #[clap(long, short = 'r', default_value_t = false)]
    rc_table: bool,

    /// dump refcount block
    #[clap(long, short = 'R', default_value_t = false, requires("rc_table"))]
    rc_block: bool,

    /// refcount block idx in refcount table
    #[clap(long, default_value_t = -1, requires("rc_block"))]
    rc_block_idx: i32,

    /// dump l1 table
    #[clap(long, short = 'l', default_value_t = false)]
    l1_table: bool,

    /// dump l2 block
    #[clap(long, short = 'L', default_value_t = false, requires("l1_table"))]
    l2_table: bool,

    /// l2 idx in l1 table
    #[clap(long, default_value_t = -1, requires("l2_table"))]
    l2_idx: i32,

    /// qcow2 image path
    file: PathBuf,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Dump all kinds of qcow2 meta data
    Dump(DumpArgs),

    /// Show qcow2 device info, and statistics for meta data
    Info(InfoArgs),

    /// Format into qcow2 image
    Format(FormatArgs),

    /// Check meta data integrity or cluster leak
    Check(CheckArgs),

    /// Map qcow2 virtual address into host cluster offset (for development only, may be removed in future)
    Map(MapArgs),
}

#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

fn dump_l1_table(
    f: &mut std::fs::File,
    info: &Qcow2Info,
    header: &Qcow2Header,
    arg: &DumpArgs,
) -> Qcow2Result<()> {
    let mut l1 = L1Table::new_empty(Some(header.l1_table_offset()), info.cluster_size());
    let l1_buf = unsafe { std::slice::from_raw_parts_mut(l1.as_mut_ptr(), l1.byte_size()) };
    assert!(l1_buf.as_ptr() == l1.as_ptr());

    //load to this refcount table from image
    f.seek(SeekFrom::Start(header.l1_table_offset()))?;
    let _bytes = f.read(l1_buf).unwrap();
    //assert!(bytes == l1.byte_size());

    println!(
        "L1Table: offset_in_image 0x{:<16x}",
        header.l1_table_offset()
    );
    for i in 0..header.l1_table_entries() {
        let e = l1.get(i);

        println!("\t idx {:<4} entry 0x{:<16x}", i, e.l2_offset());
    }

    if !arg.l2_table {
        return Ok(());
    }

    for i in 0..header.l1_table_entries() {
        let e = l1.get(i);
        let virt_l1_base = (i * info.l2_entries()) << info.cluster_shift;

        if arg.l2_idx >= 0 && (i != arg.l2_idx as usize) {
            continue;
        }

        if !e.is_zero() {
            let offset = e.l2_offset();
            let mut l2 = L2Table::new_empty(Some(offset), info.cluster_size());
            let l2_buf = unsafe { std::slice::from_raw_parts_mut(l2.as_mut_ptr(), l2.byte_size()) };
            assert!(l2_buf.as_ptr() == l2.as_ptr());

            //load to this refcount table from image
            f.seek(SeekFrom::Start(offset))?;
            let bytes = f.read(l2_buf).unwrap();
            assert!(bytes == l2.byte_size());

            println!(
                "L2Table: idx_in_table {} offset_in_image 0x{:<16x} ",
                i, offset
            );
            for j in 0..l2.entries() {
                let e = l2.get(j);

                let ol = match e.is_compressed() {
                    true => match e.compressed_range(info.cluster_shift.into()) {
                        Some(v) => v,
                        _ => (u64::MAX, 0),
                    },
                    false => (e.cluster_offset(), info.cluster_size()),
                };

                if e.cluster_offset() != 0 {
                    println!(
                        "\t virt_addr 0x{:<16x} idx {:<4} entry {:<x} off 0x{:<16x} len {:<5} compressed {} copied {}",
                        virt_l1_base + (j << info.cluster_shift),
                        j,
                        e.into_plain(),
                        ol.0, ol.1,
                        e.is_compressed(),
                        e.is_copied(),
                    );
                }
            }
        }
    }

    Ok(())
}

fn dump_refcount_table(
    f: &mut std::fs::File,
    info: &Qcow2Info,
    header: &Qcow2Header,
    arg: &DumpArgs,
) -> Qcow2Result<()> {
    let mut rc_t = RefTable::new_empty(Some(header.reftable_offset()), info.cluster_size());
    let rc_t_buf = unsafe { std::slice::from_raw_parts_mut(rc_t.as_mut_ptr(), rc_t.byte_size()) };
    assert!(rc_t_buf.as_ptr() == rc_t.as_ptr());

    //load to this refcount table from image
    f.seek(SeekFrom::Start(header.reftable_offset()))?;
    let bytes = f.read(rc_t_buf).unwrap();
    assert!(bytes == rc_t.byte_size());

    println!(
        "RefTable: offset_in_image 0x{:<16x}",
        header.reftable_offset()
    );
    for i in 0..rc_t.entries() {
        let e = rc_t.get(i);

        if !e.is_zero() {
            println!("\t idx {:4} entry 0x{:<16x}", i, e.refblock_offset());
        }
    }

    if !arg.rc_block {
        return Ok(());
    }

    for i in 0..rc_t.entries() {
        let e = rc_t.get(i);

        if arg.rc_block_idx >= 0 && i != (arg.rc_block_idx as usize) {
            continue;
        }
        if !e.is_zero() {
            let offset = e.refblock_offset();
            let mut rc_b = RefBlock::new(info.refcount_order, info.cluster_size(), Some(offset));
            let rc_b_buf =
                unsafe { std::slice::from_raw_parts_mut(rc_b.as_mut_ptr(), rc_b.byte_size()) };
            assert!(rc_b_buf.as_ptr() == rc_b.as_ptr());

            //load to this refcount table from image
            f.seek(SeekFrom::Start(offset))?;
            let bytes = f.read(rc_b_buf).unwrap();
            assert!(bytes == rc_t.byte_size());

            println!(
                "RefBlock: idx_in_table {} offset_in_image 0x{:x} ",
                i, offset
            );
            for j in 0..rc_b.entries() {
                let e = rc_b.get(j);

                let mut off = (info.rb_entries() as u64 * i as u64) << info.cluster_shift;
                off += (j as u64) << info.cluster_shift;

                if !e.is_zero() {
                    println!(
                        "\t idx {:4} entry {} for cluster 0x{:<16x}",
                        j,
                        e.into_plain(),
                        off
                    );
                }
            }
        }
    }

    Ok(())
}

fn __dump_header(f: &PathBuf, h: &Qcow2Header) {
    println!("Qcow2 Header: image {:?} length {}", f, h.header_length());
    println!("\t version\t {}", h.version());
    println!("\t virtual_size\t {} MB", h.size() >> 20);
    println!("\t cluster_size\t {} KB", 1 << (h.cluster_bits() - 10));
    println!("\t refcount_order\t {}", h.refcount_order());
    println!(
        "\t crypt_method\t {}",
        match h.crypt_method() {
            0 => "no encryption".to_string(),
            1 => "AES encryption".to_string(),
            2 => "LUKS encryption".to_string(),
            x => format!("{} ?", x),
        }
    );
    if h.header_length() >= 104 {
        println!(
            "\t compression\t {}",
            match h.compression_type() {
                0 => "zlib".to_string(),
                1 => "zstd".to_string(),
                x => format!("{} ?", x),
            }
        );
    }
    println!(
        "\t backing_file\t name {:?} format {:?}",
        h.backing_filename(),
        h.backing_format()
    );
    println!(
        "\t refcount_table\t 0x{:x} - 0x{:x}",
        h.reftable_offset(),
        h.reftable_offset() + ((h.reftable_clusters() as u64) << h.cluster_bits())
    );
    println!(
        "\t l1_table\t offset 0x{:x}, entries {}",
        h.l1_table_offset(),
        h.l1_table_entries(),
    );
    println!(
        "\t snapshots\t offset 0x{:x} nb_snapshots {}",
        h.snapshots_offset(),
        h.nb_snapshots()
    );
    println!("\t features:");
    for i in 0..4 {
        if let Some(f) = h.feature_name(Qcow2FeatureType::Incompatible, i) {
            println!("\t\t {}", f);
        }
    }
    for i in 0..1 {
        if let Some(f) = h.feature_name(Qcow2FeatureType::Compatible, i) {
            println!("\t\t {}", f);
        }
    }
    for i in 0..2 {
        if let Some(f) = h.feature_name(Qcow2FeatureType::Autoclear, i) {
            println!("\t\t {}", f);
        }
    }
}

fn dump_header(p: &PathBuf) -> Qcow2Result<()> {
    let mut f = std::fs::OpenOptions::new().read(true).open(p).unwrap();
    let mut buf = vec![0_u8; 4096];
    f.read(&mut buf).unwrap();
    let header = Qcow2Header::from_buf(&buf).unwrap();

    __dump_header(p, &header);

    Ok(())
}

fn dump_qcow2(args: DumpArgs) -> Qcow2Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .open(&args.file)
        .unwrap();
    let mut buf = vec![0_u8; 4096];
    f.read(&mut buf).unwrap();

    let p = qcow2_rs::qcow2_default_params!(true, true);
    let header = Qcow2Header::from_buf(&buf).unwrap();
    let info = Qcow2Info::new(&header, &p).unwrap();

    if !args.no_header {
        __dump_header(&args.file, &header);
    }

    if args.rc_table {
        dump_refcount_table(&mut f, &info, &header, &args).unwrap();
    }

    if args.l1_table {
        dump_l1_table(&mut f, &info, &header, &args).unwrap();
    }

    Ok(())
}

fn format_qcow2(args: FormatArgs) -> Qcow2Result<()> {
    let size = (args.size as u64) << 20;
    let cluster_bits = args.cluster_bits;
    let refcount_order = args.refcount_order;
    let bs = 512;

    //println!("{:?}", args);

    let (rc_t, rc_b, _) =
        Qcow2Header::calculate_meta_params(size, cluster_bits, refcount_order, bs);
    //println!("{:?} {:?} {:?}", rc_t, rc_b, l1_t);

    let clusters = 1 + rc_t.1 + rc_b.1;

    // just zero the 1st 512 sector of l1 table
    let img_size = ((clusters as usize) << cluster_bits) + 512;
    let mut buf = vec![0_u8; img_size];

    Qcow2Header::format_qcow2(&mut buf, size, cluster_bits, refcount_order, bs).unwrap();

    {
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&args.file)
            .unwrap();
        f.write(&mut buf).unwrap();
    }
    dump_header(&args.file).unwrap();

    Ok(())
}

fn map_qcow2(args: MapArgs) -> Qcow2Result<()> {
    let rt = Runtime::new().unwrap();
    rt.block_on(async move {
        let p = qcow2_rs::qcow2_default_params!(false, false);
        let dev = qcow2_setup_dev_tokio(&args.file, &p).await.unwrap();
        let mut start = args.addr & !dev.info.in_cluster_offset_mask as u64;

        let mut i = 0;
        while i < args.len && start < dev.info.virtual_size() {
            let mapping = dev.get_mapping(start).await.unwrap();

            if mapping.allocated() {
                println!("virt_addr {:x} mapping {}", start, mapping);
                i += 1;
            }

            start += dev.info.cluster_size() as u64;
        }
    });

    Ok(())
}

fn info_qcow2(args: InfoArgs) -> Qcow2Result<()> {
    let rt = Runtime::new().unwrap();
    rt.block_on(async move {
        let p = qcow2_rs::qcow2_default_params!(true, false);
        let dev = qcow2_setup_dev_tokio(&args.file, &p).await.unwrap();
        let info = &dev.info;
        println!("{:?}", dev);

        let total_clusters = info.virtual_size() >> info.cluster_bits();
        println!(
            "virtual size {}MB / {} clusters, cluster size {} byte",
            info.virtual_size() >> 20,
            total_clusters,
            info.cluster_size(),
        );
        println!("Host clusters usage");
        println!(
            "\t{:<16}: alloc {:10} compressed {:10} used {:10}",
            "header", 1, 0, 1
        );
        if args.verbose {
            println!("\t\t {:<#016x} - 0x{:<#016x}", 0, 0);
        }

        let used = std::cell::RefCell::new(1);
        let mapped = std::cell::RefCell::new(1_u64);
        let meta = std::cell::RefCell::new(1_u64);
        let compressed = std::cell::RefCell::new(0_u64);

        dev.qcow2_cluster_usage(|info, ranges, allocated| {
            let mut sum = 0;
            for r in ranges {
                sum += r.end() - r.start() + 1;
            }
            let (alloc, comp) = match allocated {
                Some(a) => a,
                None => (sum.try_into().unwrap(), 0),
            };
            *used.borrow_mut() += sum;
            *mapped.borrow_mut() += alloc as u64;
            *compressed.borrow_mut() += comp as u64;
            if info != "data" {
                *meta.borrow_mut() += sum;
            }

            println!(
                "\t{:<16}: alloc {:10} compressed {:10} used {:10}",
                info, alloc, comp, sum
            );
            if args.verbose {
                for r in ranges {
                    println!(
                        "\t\t {:<#016x} - {:<#016x}",
                        r.start() << dev.info.cluster_bits(),
                        r.end() << dev.info.cluster_bits()
                    );
                }
            }
        })
        .await
        .unwrap();

        let mapped_cnt = *mapped.borrow();
        let used_ratio = *used.borrow() * 100 / total_clusters;
        let alloc_ratio = mapped_cnt * 100 / total_clusters;
        let compressed_ratio =
            *compressed.borrow() * 100 / (if mapped_cnt == 0 { 1 } else { mapped_cnt });
        println!(
            "Total {} meta {}: {}/{}% allocated: {}/{}% compressed, {}/{}% used",
            total_clusters,
            *meta.borrow(),
            *mapped.borrow(),
            alloc_ratio,
            *compressed.borrow(),
            compressed_ratio,
            *used.borrow(),
            used_ratio
        );
    });
    Ok(())
}

fn check_qcow2(args: CheckArgs) -> Qcow2Result<()> {
    let rt = Runtime::new().unwrap();

    rt.block_on(async move {
        let p = qcow2_rs::qcow2_default_params!(false, false);
        let dev = qcow2_setup_dev_tokio(&args.file, &p).await.unwrap();

        dev.check().await.expect("check failed");
    });

    Ok(())
}

fn main() {
    let cli = Cli::parse();

    env_logger::builder()
        .format_target(false)
        .format_timestamp(None)
        .init();

    match cli.command {
        Commands::Dump(arg) => dump_qcow2(arg).unwrap(),
        Commands::Format(arg) => format_qcow2(arg).unwrap(),
        Commands::Map(arg) => map_qcow2(arg).unwrap(),
        Commands::Info(arg) => info_qcow2(arg).unwrap(),
        Commands::Check(arg) => check_qcow2(arg).unwrap(),
    };
}
