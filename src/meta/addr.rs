use crate::dev::Qcow2Info;

#[derive(Debug, Clone)]
pub struct SplitGuestOffset(pub u64);

impl SplitGuestOffset {
    #[inline(always)]
    pub fn guest_addr(&self) -> u64 {
        self.0
    }

    #[inline(always)]
    pub fn cluster_offset(&self, info: &Qcow2Info) -> u64 {
        let cluster_bits = info.cluster_bits();
        (((self.l1_index(info) as u64) << (cluster_bits - 3)) + self.l2_index(info) as u64)
            << cluster_bits
    }

    #[inline(always)]
    pub fn l1_index(&self, info: &Qcow2Info) -> usize {
        let guest_offset = self.0 >> (info.cluster_shift + info.l2_index_shift);
        guest_offset.try_into().unwrap()
    }

    #[inline(always)]
    pub fn l2_index(&self, info: &Qcow2Info) -> usize {
        let guest_offset = self.0 >> info.cluster_bits();
        guest_offset as usize & info.l2_index_mask
    }

    #[inline(always)]
    pub fn l2_slice_index(&self, info: &Qcow2Info) -> usize {
        let guest_offset = self.0 >> info.cluster_bits();
        guest_offset as usize & (info.l2_slice_entries as usize - 1)
    }

    #[inline(always)]
    pub fn l2_slice_key(&self, info: &Qcow2Info) -> usize {
        (self.0 >> (info.cluster_shift + info.l2_slice_index_shift)) as usize
    }

    #[inline(always)]
    pub fn l2_slice_off_in_table(&self, info: &Qcow2Info) -> usize {
        let l2_idx = self.l2_index(info);

        //todo: support extended l2 descriptor
        (l2_idx >> info.l2_slice_index_shift) << info.l2_slice_bits
    }

    #[inline(always)]
    pub fn in_cluster_offset(&self, info: &Qcow2Info) -> usize {
        self.0 as usize & info.in_cluster_offset_mask
    }
}
