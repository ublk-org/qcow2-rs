use super::table::{
    impl_entry_display_trait, impl_table_gen_funcs, impl_table_gen_setter,
    impl_top_table_gen_funcs, impl_top_table_traits, Table, TableEntry,
};
use crate::dev::Qcow2Info;
use crate::error::Qcow2Result;
use crate::helpers::Qcow2IoBuf;
use std::cell::RefCell;
use std::collections::VecDeque;

impl_entry_display_trait!(RefTableEntry);
impl_entry_display_trait!(RefBlockEntry);

#[derive(Copy, Clone, Default, Debug)]
pub struct RefTableEntry(pub u64);

impl RefTableEntry {
    pub fn refblock_offset(&self) -> u64 {
        self.0 & 0xffff_ffff_ffff_fe00u64
    }

    pub fn is_zero(&self) -> bool {
        self.refblock_offset() == 0
    }

    pub fn reserved_bits(&self) -> u64 {
        self.0 & 0x0000_0000_0000_01ffu64
    }
}

impl TableEntry for RefTableEntry {
    fn try_from_plain(value: u64, qcow2_info: &Qcow2Info) -> Qcow2Result<Self> {
        let entry = RefTableEntry(value);

        if entry.reserved_bits() != 0 {
            return Err(format!(
                "Invalid reftable entry 0x{:x}, reserved bits set (0x{:x})",
                value,
                entry.reserved_bits()
            )
            .into());
        }

        if qcow2_info.in_cluster_offset(entry.refblock_offset()) != 0 {
            return Err(format!(
                "Invalid reftable entry 0x{:x}, offset (0x{:x}) is not aligned to cluster size (0x{:x})",
                value,
                entry.refblock_offset(),
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
        self.refblock_offset()
    }
}

#[derive(Debug)]
pub struct RefTable {
    dirty_blocks: RefCell<VecDeque<u32>>,
    bs_bits: u8,
    offset: Option<u64>,
    data: Qcow2IoBuf<RefTableEntry>,
}

impl RefTable {
    pub fn new(offset: Option<u64>, size: usize, bs_bits: u8) -> Self {
        let mut rt = RefTable::new_empty(offset, size);

        rt.bs_bits = bs_bits;
        rt
    }

    /// Create a clone that covers at least `at_least_index`
    pub fn clone_and_grow(&self, clusters: usize, cluster_size: usize, bs: usize) -> Self {
        let entry_size = core::mem::size_of::<RefTableEntry>();
        let ram_size = self.data.len() * entry_size;

        //table in ram may not reach end of reftable in disk
        let (new_size, new_off) = if ram_size + entry_size < clusters * cluster_size {
            (ram_size + entry_size, self.offset)
        } else {
            (clusters * cluster_size + bs, None)
        };

        let mut new_data = Qcow2IoBuf::<RefTableEntry>::new(new_size);
        new_data.zero_buf();
        new_data[..self.data.len()].copy_from_slice(&self.data);

        Self {
            offset: new_off,
            data: new_data,
            dirty_blocks: RefCell::new(self.dirty_blocks.borrow().clone()),
            bs_bits: self.bs_bits,
        }
    }

    pub fn in_bounds(&self, index: usize) -> bool {
        index < self.data.len()
    }

    pub fn set_refblock_offset(&mut self, index: usize, rb_offset: u64) {
        let rt_entry = RefTableEntry(rb_offset);
        debug_assert!(rt_entry.reserved_bits() == 0);

        self.set(index, rt_entry);
        self.set_dirty(index);
    }
}

impl From<Qcow2IoBuf<RefTableEntry>> for RefTable {
    fn from(data: Qcow2IoBuf<RefTableEntry>) -> Self {
        Self {
            data,
            dirty_blocks: RefCell::new(VecDeque::new()),
            bs_bits: 0,
            offset: None,
        }
    }
}

impl_top_table_traits!(RefTable, RefTableEntry, data);

#[derive(Copy, Clone, Default, Debug)]
pub struct RefBlockEntry(u64);

impl RefBlockEntry {
    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }
}
impl TableEntry for RefBlockEntry {
    #[inline(always)]
    fn try_from_plain(value: u64, _qcow2_info: &Qcow2Info) -> Qcow2Result<Self> {
        Ok(RefBlockEntry(value))
    }

    #[inline(always)]
    fn into_plain(self) -> u64 {
        self.0
    }
}

#[derive(Debug)]
pub struct RefBlock {
    offset: Option<u64>,
    raw_data: Qcow2IoBuf<RefBlockEntry>,
    refcount_order: u8,
}

impl RefBlock {
    pub fn new(refcount_order: u8, size: usize, offset: Option<u64>) -> Self {
        let mut rb = RefBlock::new_empty(offset, size);

        rb.set_refcount_order(refcount_order);
        rb
    }

    pub fn set_refcount_order(&mut self, refcount_order: u8) {
        self.refcount_order = refcount_order;
    }

    #[inline(always)]
    fn __get(&self, index: usize) -> u64 {
        let raw_data = &self.raw_data.as_u8_slice();
        match self.refcount_order {
            // refcount_bits == 1
            0 => ((raw_data[index / 8] >> (index % 8)) & 0b0000_0001) as u64,

            // refcount_bits == 2
            1 => ((raw_data[index / 4] >> ((index % 4) * 2)) & 0b0000_0011) as u64,

            // refcount_bits == 4
            2 => ((raw_data[index / 2] >> ((index % 2) * 4)) & 0b0000_1111) as u64,

            // refcount_bits == 8
            3 => raw_data[index] as u64,

            // refcount_bits == 16
            4 => u16::from_be_bytes(raw_data[index * 2..index * 2 + 2].try_into().unwrap()) as u64,

            // refcount_bits == 32
            5 => u32::from_be_bytes(raw_data[index * 4..index * 4 + 4].try_into().unwrap()) as u64,

            // refcount_bits == 64
            6 => u64::from_be_bytes(raw_data[index * 8..index * 8 + 8].try_into().unwrap()),

            _ => unreachable!(),
        }
    }

    fn __set(&mut self, index: usize, value: u64) -> Qcow2Result<()> {
        // refcount_bits == 64 can hold any value
        if self.refcount_order < 6 {
            let refcount_bits = 1u64 << self.refcount_order;
            let max = (1u64 << refcount_bits) - 1;

            if value > max {
                return Err(format!(
                    "Cannot increase refcount beyond {max} with refcount_bits={refcount_bits}"
                )
                .into());
            }
        }

        let raw_data = &mut self.raw_data.as_u8_slice_mut();
        match self.refcount_order {
            // refcount_bits == 1
            0 => {
                raw_data[index / 8] = (raw_data[index / 8] & !(0b0000_0001 << (index % 8)))
                    | ((value as u8) << (index % 8));
            }

            // refcount_bits == 2
            1 => {
                let shift = (index % 4) * 2;
                raw_data[index / 4] =
                    (raw_data[index / 4] & !(0b0000_0011 << shift)) | ((value as u8) << shift);
            }

            // refcount_bits == 4
            2 => {
                let shift = (index % 2) * 4;
                raw_data[index / 2] =
                    (raw_data[index / 2] & !(0b0000_1111 << shift)) | ((value as u8) << shift);
            }

            // refcount_bits == 8
            3 => {
                raw_data[index] = value as u8;
            }

            // refcount_bits == 16
            4 => {
                raw_data[index * 2] = (value >> 8) as u8;
                raw_data[index * 2 + 1] = value as u8;
            }

            // refcount_bits == 32
            5 => {
                raw_data[index * 4] = (value >> 24) as u8;
                raw_data[index * 4 + 1] = (value >> 16) as u8;
                raw_data[index * 4 + 2] = (value >> 8) as u8;
                raw_data[index * 4 + 3] = value as u8;
            }

            // refcount_bits == 64
            6 => {
                let array: &mut [u8; 8] = (&mut raw_data[index * 8..index * 8 + 8])
                    .try_into()
                    .unwrap();
                *array = value.to_be_bytes();
            }

            _ => unreachable!(),
        }

        Ok(())
    }

    pub fn increment(&mut self, index: usize) -> Qcow2Result<()> {
        let val = self
            .get(index)
            .into_plain()
            .checked_add(1)
            .ok_or_else(|| format!("Cannot increase refcount beyond {}", u64::MAX))?;
        self.__set(index, val)
    }

    pub fn decrement(&mut self, index: usize) -> Qcow2Result<()> {
        let val = self
            .get(index)
            .into_plain()
            .checked_sub(1)
            .ok_or("Cannot decrease refcount below 0")?;
        self.__set(index, val)
    }

    fn check_if_free(&self, r: std::ops::Range<usize>) -> bool {
        for i in r {
            if !self.get(i).is_zero() {
                return false;
            }
        }
        true
    }

    pub fn get_free_range(&self, start: usize, count: usize) -> Option<std::ops::Range<usize>> {
        assert!(start + count <= self.entries());
        let max_start = self.entries() - count;

        for i in start..=max_start {
            if self.check_if_free(i..i + count) {
                return Some(i..i + count);
            }
        }

        None
    }

    pub fn get_tail_free_range(&self) -> Option<std::ops::Range<usize>> {
        let r = 0..self.entries();

        for i in r.rev() {
            if !self.get(i).is_zero() {
                if i == self.entries() - 1 {
                    break;
                }
                return Some(i + 1..self.entries());
            }
        }
        None
    }

    pub fn alloc_range(&mut self, s: usize, e: usize) -> Qcow2Result<()> {
        for i in s..e {
            self.increment(i)?;
        }
        Ok(())
    }
}

impl Table for RefBlock {
    type Entry = RefBlockEntry;

    impl_table_gen_funcs!(raw_data);

    fn entries(&self) -> usize {
        self.byte_size() * 8 / (1 << self.refcount_order)
    }

    fn get(&self, index: usize) -> Self::Entry {
        RefBlockEntry(self.__get(index))
    }

    fn set(&mut self, index: usize, value: Self::Entry) {
        self.__set(index, value.into_plain()).unwrap();
    }

    /// RefBlock is special, since RefBlockEntry is defined as u64
    fn byte_size(&self) -> usize {
        self.raw_data.len() * 8
    }
}

impl From<Qcow2IoBuf<RefBlockEntry>> for RefBlock {
    fn from(data: Qcow2IoBuf<RefBlockEntry>) -> Self {
        Self {
            offset: None,
            refcount_order: 0,
            raw_data: data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::{Table, TableEntry};

    #[test]
    fn test_refcount_table() {
        let cluster_size = 1 << 16;
        let size = 4096;

        let mut rc = RefTable::new_empty(Some(cluster_size), 4096);
        assert!(rc.entries() == (size / core::mem::size_of::<u64>()));
        assert!(rc.as_ptr() != std::ptr::null());

        let entry = rc.get(0);
        assert!(entry.is_zero() == true);

        let rcb_offset = cluster_size * 3;
        rc.set(0, RefTableEntry(rcb_offset));
        let entry = rc.get(0);
        assert!(entry.refblock_offset() == rcb_offset);

        let raw_addr = rc.as_ptr() as *const u64;
        unsafe {
            assert!(u64::from_be(*raw_addr) == rcb_offset);
        };
    }

    #[test]
    fn test_refcount_block() {
        let cluster_size = 1 << 16;
        let size = 4096;
        let refcount_order = 4;
        let entries = size * 8 / (1 << refcount_order);

        let mut rc_b = RefBlock::new(refcount_order, size, Some(2 * cluster_size));
        assert!(rc_b.entries() == entries);
        assert!(rc_b.as_ptr() != std::ptr::null());

        for i in 0..entries {
            let entry = rc_b.get(i).into_plain();
            assert!(entry == 0);
            rc_b.increment(i).unwrap();
            let entry = rc_b.get(i).into_plain();
            assert!(entry == 1);
        }
    }

    /// more detailed unit test generated by AI with small fixes
    #[test]
    fn test_refcount_block2() {
        let mut refblock = RefBlock::new(3, 4096, Some(0));
        assert_eq!(refblock.entries(), 4096);
        assert_eq!(refblock.byte_size(), 4096);
        assert_eq!(refblock.get_offset(), Some(0));

        assert!(refblock.get(0).is_zero());

        assert!(refblock.increment(0).is_ok());
        assert_eq!(refblock.get(0).into_plain(), 1);

        assert!(refblock.decrement(0).is_ok());
        assert_eq!(refblock.get(0).into_plain(), 0);

        assert!(refblock.__set(0, 255).is_ok());
        assert!(refblock.__set(0, 1).is_ok());
        assert_eq!(refblock.get(0).into_plain(), 1);

        assert!(refblock.__set(0, 256).is_err());
        assert!(refblock.__set(0, 255).is_ok());
        assert_eq!(refblock.get(0).into_plain(), 255);

        assert!(refblock.__set(0, u16::MAX as u64 + 1).is_err());
        assert!(refblock.__set(0, u16::MAX as u64).is_err());

        assert!(refblock.__set(0, u32::MAX as u64 + 1).is_err());
        assert!(refblock.__set(0, u32::MAX as u64).is_err());

        assert!(refblock.__set(0, u64::MAX).is_err());
    }
}
