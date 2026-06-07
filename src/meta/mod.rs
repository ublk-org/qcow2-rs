// borrowed from rsd project

#![allow(dead_code)]

mod addr;
mod header;
mod l1;
mod l2;
mod refcount;
mod table;

pub use self::addr::SplitGuestOffset;
pub use self::header::*;
pub use self::l1::{L1Entry, L1Table};
pub use self::l2::{L2Entry, L2Table, Mapping, MappingSource};
pub use self::refcount::{RefBlock, RefBlockEntry, RefTable, RefTableEntry};
pub use self::table::{Table, TableEntry};

#[cfg(test)]
mod tests {
    use crate::dev::*;
    use crate::meta::*;

    #[test]
    fn test_format() {
        fn __test_format(cluster_bits: usize, refcount_order: u8, size: u64) {
            let p = crate::qcow2_default_params!(true, true);
            let bs = 1 << p.get_bs_bits();
            let (rc_t, rc_b, _) =
                Qcow2Header::calculate_meta_params(size, cluster_bits, refcount_order, bs);
            let clusters = 1 + rc_t.1 + rc_b.1;
            let img_size = ((clusters as usize) << cluster_bits) + 512;
            let mut buf = vec![0u8; img_size];

            Qcow2Header::format_qcow2(&mut buf, size, cluster_bits, refcount_order, bs).unwrap();

            let header = Qcow2Header::from_buf(&buf).unwrap();
            let info = Qcow2Info::new(&header, &p).unwrap();

            assert!(info.cluster_bits() == cluster_bits);
            assert!(info.virtual_size() == size);
            assert!(info.refcount_order() == refcount_order);
        }

        let sizes = [64 << 20, 64 << 30, 2 << 40];

        for c in 13..21 {
            for r in 1..7 {
                for s in sizes {
                    __test_format(c, r, s);
                }
            }
        }
    }
}
