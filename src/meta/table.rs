// borrowed from rsd project

use crate::dev::Qcow2Info;
use crate::error::Qcow2Result;
use crate::helpers::Qcow2IoBuf;
use std::mem::size_of;

macro_rules! impl_table_gen_funcs {
    ($field:ident) => {
        #[inline(always)]
        fn as_ptr(&self) -> *const u8 {
            self.$field.as_ptr() as *const u8
        }

        #[inline(always)]
        fn as_mut_ptr(&mut self) -> *mut u8 {
            self.$field.as_mut_ptr() as *mut u8
        }

        #[inline(always)]
        fn get_offset(&self) -> Option<u64> {
            self.offset
        }

        #[inline(always)]
        fn set_offset(&mut self, offset: Option<u64>) {
            self.offset = offset;
        }
    };
}

macro_rules! impl_table_gen_setter {
    ($entry:ident, $field:ident) => {
        #[inline(always)]
        fn entries(&self) -> usize {
            self.$field.len()
        }

        #[inline(always)]
        fn get(&self, index: usize) -> $entry {
            match self.$field.get(index) {
                Some(entry) => $entry(u64::from_be(entry.0)),
                None => $entry(0),
            }
        }

        #[inline(always)]
        fn set(&mut self, index: usize, entry: $entry) {
            self.$field[index] = $entry(entry.0.to_be());
        }
    };
}

macro_rules! impl_top_table_gen_funcs {
    () => {
        #[inline(always)]
        fn set_dirty(&self, idx: usize) {
            let bs_idx = ((idx as u32) << 3) >> self.bs_bits;
            let mut blkq = self.dirty_blocks.borrow_mut();

            if !blkq.contains(&bs_idx) {
                blkq.push_back(bs_idx);
            }
        }

        /// Remove specified data iff val isn't None
        #[inline(always)]
        fn pop_dirty_blk_idx(&self, val: Option<u32>) -> Option<u32> {
            let mut blkq = self.dirty_blocks.borrow_mut();

            match val {
                Some(data) => match blkq.iter().position(|x| *x == data) {
                    Some(pos) => {
                        blkq.remove(pos);
                        Some(data)
                    }
                    None => None,
                },
                None => blkq.pop_front(),
            }
        }
    };
}

macro_rules! impl_table_traits {
    ($table:ident, $entry:ident, $field:ident) => {
        impl Table for $table {
            type Entry = $entry;

            impl_table_gen_funcs!($field);
            impl_table_gen_setter!($entry, $field);
        }
    };
}

macro_rules! impl_top_table_traits {
    ($table:ident, $entry:ident, $field:ident) => {
        impl Table for $table {
            type Entry = $entry;

            impl_table_gen_funcs!($field);
            impl_table_gen_setter!($entry, $field);
            impl_top_table_gen_funcs!();
        }
    };
}

macro_rules! impl_entry_display_trait {
    ($entry:ident) => {
        impl std::fmt::Display for $entry {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{:<16x}", self.into_plain())
            }
        }
    };
}

pub trait TableEntry
where
    Self: Copy + Sized + std::fmt::Debug,
{
    fn try_from_plain(value: u64, qcow2_info: &Qcow2Info) -> Qcow2Result<Self>;
    fn into_plain(self) -> u64;

    /// Only for top table to return offset stored
    #[inline(always)]
    fn get_value(&self) -> u64 {
        panic!();
    }
}

pub trait Table: From<Qcow2IoBuf<Self::Entry>> {
    type Entry: TableEntry;

    fn entries(&self) -> usize;
    fn get(&self, index: usize) -> Self::Entry;
    fn set(&mut self, index: usize, value: Self::Entry);
    fn get_offset(&self) -> Option<u64>;
    fn set_offset(&mut self, offset: Option<u64>);

    fn as_ptr(&self) -> *const u8;
    fn as_mut_ptr(&mut self) -> *mut u8;

    fn byte_size(&self) -> usize {
        self.entries() * size_of::<u64>()
    }

    fn cluster_count(&self, qcow2_info: &Qcow2Info) -> usize {
        self.byte_size().div_ceil(qcow2_info.cluster_size())
    }

    fn is_update(&self) -> bool {
        self.get_offset().is_some()
    }

    fn new_empty(offset: Option<u64>, size: usize) -> Self {
        let mut table = Qcow2IoBuf::<Self::Entry>::new(size);
        table.zero_buf();

        let mut table: Self = table.into();
        table.set_offset(offset);

        table
    }

    #[inline(always)]
    fn set_dirty(&self, _idx: usize) {}

    #[inline(always)]
    fn pop_dirty_blk_idx(&self, _val: Option<u32>) -> Option<u32> {
        None
    }
}

pub(crate) use impl_entry_display_trait;
pub(crate) use impl_table_gen_funcs;
pub(crate) use impl_table_gen_setter;
pub(crate) use impl_table_traits;
pub(crate) use impl_top_table_gen_funcs;
pub(crate) use impl_top_table_traits;
