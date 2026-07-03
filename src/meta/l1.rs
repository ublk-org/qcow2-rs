use super::table::{
    impl_entry_display_trait, impl_table_gen_funcs, impl_table_gen_setter,
    impl_top_table_gen_funcs, impl_top_table_traits, Table, TableEntry,
};
use crate::dev::Qcow2Info;
use crate::error::Qcow2Result;
use crate::helpers::{IntAlignment, Qcow2IoBuf};
use std::cell::RefCell;
use std::collections::VecDeque;

impl_entry_display_trait!(L1Entry);

// L1 table entry:
//
// Bit  0 -  8:     Reserved (set to 0)
//
//      9 - 55:     Bits 9-55 of the offset into the image file at which the L2
//                  table starts. Must be aligned to a cluster boundary. If the
//                  offset is 0, the L2 table and all clusters described by this
//                  L2 table are unallocated.
//
//      56 - 62:    Reserved (set to 0)
//
//      63:         0 for an L2 table that is unused or requires COW, 1 if its
//                  refcount is exactly one. This information is only accurate
//                  in the active L1 table.
#[derive(Copy, Clone, Default, Debug)]
pub struct L1Entry(u64);

impl L1Entry {
    pub fn l2_offset(&self) -> u64 {
        self.0 & 0x00ff_ffff_ffff_fe00u64
    }

    pub fn is_copied(&self) -> bool {
        self.0 & (1u64 << 63) != 0
    }

    pub fn is_zero(&self) -> bool {
        self.l2_offset() == 0
    }

    pub fn reserved_bits(&self) -> u64 {
        self.0 & 0x7f00_0000_0000_01feu64
    }
}

impl TableEntry for L1Entry {
    fn try_from_plain(value: u64, qcow2_info: &Qcow2Info) -> Qcow2Result<Self> {
        let entry = L1Entry(value);

        if entry.reserved_bits() != 0 {
            return Err(format!(
                "Invalid L1 entry 0x{:x}, reserved bits set (0x{:x})",
                value,
                entry.reserved_bits()
            )
            .into());
        }

        if qcow2_info.in_cluster_offset(entry.l2_offset()) != 0 {
            return Err(format!(
                "Invalid L1 entry 0x{:x}, offset (0x{:x}) is not aligned to cluster size (0x{:x})",
                value,
                entry.l2_offset(),
                qcow2_info.cluster_size()
            )
            .into());
        }

        Ok(entry)
    }

    #[inline(always)]
    fn into_plain(self) -> u64 {
        self.0
    }

    #[inline(always)]
    fn get_value(&self) -> u64 {
        self.l2_offset()
    }
}

#[derive(Debug)]
pub struct L1Table {
    header_entries: u32,
    dirty_blocks: RefCell<VecDeque<u32>>,
    bs_bits: u8,
    offset: Option<u64>,
    data: Qcow2IoBuf<L1Entry>,
}

impl L1Table {
    pub fn new(offset: Option<u64>, data_size: usize, header_entries: u32, bs_bits: u8) -> Self {
        let mut l1 = L1Table::new_empty(offset, data_size);
        l1.header_entries = header_entries;
        l1.bs_bits = bs_bits;
        l1
    }

    pub fn update_header_entries(&mut self, entries: u32) {
        assert!((entries as usize) <= self.data.len());
        self.header_entries = entries;
    }

    /// Create a clone that covers at least `at_least_index`
    pub fn clone_and_grow(&self, at_least_index: usize, cluster_size: usize) -> Self {
        let new_size = std::cmp::max(at_least_index + 1, self.data.len());
        let new_size = new_size.align_up(cluster_size).unwrap();
        let mut new_data = Qcow2IoBuf::<L1Entry>::new(new_size);
        new_data[..self.data.len()].copy_from_slice(&self.data);

        Self {
            offset: None,
            data: new_data,
            bs_bits: self.bs_bits,
            header_entries: self.data.len() as u32,
            dirty_blocks: RefCell::new(self.dirty_blocks.borrow().clone()),
        }
    }

    pub fn in_bounds(&self, index: usize) -> bool {
        index < self.header_entries as usize
    }

    pub fn map_l2_offset(&mut self, index: usize, l2_offset: u64) {
        let l1entry = L1Entry((1 << 63) | l2_offset);
        debug_assert!(l1entry.reserved_bits() == 0);
        self.set(index, l1entry);
        self.set_dirty(index);
    }
}

impl_top_table_traits!(L1Table, L1Entry, data);

impl From<Qcow2IoBuf<L1Entry>> for L1Table {
    fn from(data: Qcow2IoBuf<L1Entry>) -> Self {
        Self {
            bs_bits: 0,
            header_entries: 0,
            offset: None,
            data,
            dirty_blocks: RefCell::new(VecDeque::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::Table;

    #[test]
    fn test_l1_table() {
        let cluster_size = 1 << 16;
        let size = 4096;

        let mut l1 = L1Table::new_empty(Some(cluster_size), 4096);
        assert!(l1.entries() == (size / core::mem::size_of::<u64>()));
        assert!(!l1.as_ptr().is_null());

        let entry = l1.get(0);
        assert!(entry.is_zero());

        let l2_offset = cluster_size * 3;
        l1.set(0, L1Entry(l2_offset));
        let entry = l1.get(0);
        assert!(entry.l2_offset() == l2_offset);

        let raw_addr = l1.as_ptr() as *const u64;
        unsafe {
            assert!(u64::from_be(*raw_addr) == l2_offset);
        };
    }
}
