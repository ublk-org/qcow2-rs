use crate::error::Qcow2Result;
use crate::helpers::{IntAlignment, Qcow2IoBuf};
use crate::meta::{L2Entry, Mapping, MappingSource, SplitGuestOffset};
use crate::zero_buf;
use async_recursion::async_recursion;
use miniz_oxide::inflate::core::{decompress as inflate, DecompressorOxide};
use miniz_oxide::inflate::TINFLStatus;

use super::*;

impl<T: Qcow2IoOps> Qcow2Dev<T> {
    pub async fn get_mapping(&self, virtual_offset: u64) -> Qcow2Result<Mapping> {
        let split = SplitGuestOffset(self.info.cluster_round_down(virtual_offset));
        let entry = self.get_l2_entry(virtual_offset).await?;

        Ok(entry.into_mapping(&self.info, &split))
    }

    #[inline]
    pub(crate) async fn get_l2_entry(&self, virtual_offset: u64) -> Qcow2Result<L2Entry> {
        let info = &self.info;
        let split = SplitGuestOffset(virtual_offset);
        let key = split.l2_slice_key(info);

        // fast path
        if let Some(res) = self.l2cache.get(key) {
            let l2_slice = res.value().read().await;
            Ok(l2_slice.get_entry(info, &split))
        } else {
            let l1_entry = self.get_l1_entry(&split).await?;

            if l1_entry.is_zero() {
                Ok(L2Entry(0))
            } else {
                let entry = self.get_l2_slice_slow(&l1_entry, &split).await?;
                let l2_slice = entry.value().read().await;
                Ok(l2_slice.get_entry(info, &split))
            }
        }
    }

    #[inline]
    async fn get_l2_entries(&self, off: u64, len: usize) -> Qcow2Result<Vec<L2Entry>> {
        let info = &self.info;
        let start = info.cluster_round_down(off);
        let end = info.cluster_round_up(off + len as u64);
        let mut entries = Vec::with_capacity(((end - start) as usize) >> info.cluster_bits());
        let mut voff = start;

        while voff < end {
            let split = SplitGuestOffset(voff);
            let key = split.l2_slice_key(info);

            // fast path
            let l2_slice = match self.l2cache.get(key) {
                Some(res) => res.value().read().await,
                None => {
                    let l1_entry = self.get_l1_entry(&split).await?;

                    if l1_entry.is_zero() {
                        entries.push(L2Entry(0));
                        voff += info.cluster_size() as u64;
                        continue;
                    } else {
                        let entry = self.get_l2_slice_slow(&l1_entry, &split).await?;
                        entry.value().read().await
                    }
                }
            };

            let this_end = {
                let l2_slice_idx = split.l2_slice_index(info) as u32;
                std::cmp::min(
                    end,
                    voff + (((info.l2_slice_entries - l2_slice_idx) as u64) << info.cluster_bits()),
                )
            };

            for this_off in (voff..this_end).step_by(info.cluster_size()) {
                let s = SplitGuestOffset(this_off);
                entries.push(l2_slice.get_entry(info, &s));
            }
            voff = this_end;
        }

        Ok(entries)
    }

    pub(crate) async fn do_read_compressed(
        &self,
        mapping: Mapping,
        off_in_cls: usize,
        buf: &mut [u8],
    ) -> Qcow2Result<usize> {
        let info = &self.info;
        let compressed_offset = mapping.cluster_offset.unwrap();
        let compressed_length = mapping.compressed_length.unwrap();

        // for supporting dio, we have to run aligned IO
        let bs = 1_usize << info.block_size_shift;
        let aligned_off = compressed_offset.align_down(bs as u64).unwrap();
        let pad = (compressed_offset - aligned_off) as usize;
        let aligned_len = (pad + compressed_length).align_up(bs).unwrap();

        let mut _compressed_data = Qcow2IoBuf::<u8>::new(aligned_len);
        let res = self.call_read(aligned_off, &mut _compressed_data).await?;
        if res != aligned_len {
            return Err("do_read_compressed: short read compressed data".into());
        }
        let compressed_data = &_compressed_data[pad..(pad + compressed_length)];

        // inflate straight into `buf` when it covers the whole cluster,
        // otherwise into a temporary cluster buffer and copy the wanted part
        let mut whole_cluster =
            (buf.len() != info.cluster_size()).then(|| vec![0; info.cluster_size()]);
        let dst: &mut [u8] = match whole_cluster.as_deref_mut() {
            Some(tmp) => tmp,
            None => buf,
        };

        let mut dec_ox = DecompressorOxide::new();
        let (status, _read, _written) = inflate(&mut dec_ox, compressed_data, dst, 0, 0);
        if status != TINFLStatus::Done && status != TINFLStatus::HasMoreOutput {
            return Err(format!(
                "Failed to decompress cluster (host offset 0x{compressed_offset:x}+{compressed_length}): {status:?}"
            )
            .into());
        }

        if let Some(tmp) = whole_cluster {
            buf.copy_from_slice(&tmp[off_in_cls..(off_in_cls + buf.len())]);
        }

        Ok(buf.len())
    }

    #[inline]
    async fn do_read_backing(
        &self,
        mapping: Mapping,
        off_in_cls: usize,
        buf: &mut [u8],
    ) -> Qcow2Result<usize> {
        match self.backing_file.as_ref() {
            Some(backing) => match mapping.cluster_offset {
                Some(off) => {
                    backing
                        .read_at_for_backing(buf, off + off_in_cls as u64)
                        .await
                }
                None => Err("Backing mapping: None offset None".into()),
            },
            None => {
                zero_buf!(buf);
                Ok(buf.len())
            }
        }
    }

    #[inline]
    async fn do_read_zero(&self, buf: &mut [u8]) -> Qcow2Result<usize> {
        zero_buf!(buf);
        Ok(buf.len())
    }

    #[inline]
    async fn do_read_data_file(
        &self,
        mapping: Mapping,
        off_in_cls: usize,
        buf: &mut [u8],
    ) -> Qcow2Result<usize> {
        match mapping.cluster_offset {
            Some(off) => self.call_read(off + off_in_cls as u64, buf).await,
            None => Err("DataFile mapping: None offset None".into()),
        }
    }

    #[inline]
    async fn do_read(&self, entry: L2Entry, offset: u64, buf: &mut [u8]) -> Qcow2Result<usize> {
        let off_in_cls = self.info.in_cluster_offset(offset);
        let split = SplitGuestOffset(offset - (off_in_cls as u64));
        let mapping = entry.into_mapping(&self.info, &split);

        log::trace!(
            "do_read: {} off_in_cls {} len {}",
            mapping,
            off_in_cls,
            buf.len()
        );
        match mapping.source {
            MappingSource::DataFile => self.do_read_data_file(mapping, off_in_cls, buf).await,
            MappingSource::Zero | MappingSource::Unallocated => self.do_read_zero(buf).await,
            MappingSource::Backing => self.do_read_backing(mapping, off_in_cls, buf).await,
            MappingSource::Compressed => self.do_read_compressed(mapping, off_in_cls, buf).await,
        }
    }

    #[inline]
    async fn __read_at(&self, buf: &mut [u8], mut offset: u64) -> Qcow2Result<usize> {
        let info = &self.info;
        let bs = 1 << info.block_size_shift;
        let bs_mask = bs - 1;
        let vsize = info.virtual_size();
        let mut len = buf.len();
        let old_offset = offset;
        let old_len = len;
        let single =
            (offset >> info.cluster_bits()) == ((offset + (len as u64) - 1) >> info.cluster_bits());

        if offset >= vsize {
            if !info.is_back_file() {
                return Err("read_at eof".into());
            } else {
                // the top device is asking for read, which is usually
                // caused by top device resize, so simply fake we provide
                // data requested
                return Ok(buf.len());
            }
        }

        if len == 0 {
            return Ok(0);
        }

        if (len & bs_mask) != 0 {
            return Err("un-aligned buffer length".into());
        }

        if (offset & (bs_mask as u64)) != 0 {
            return Err("un-aligned offset".into());
        }

        log::debug!("read_at: offset {:x} len {} >>>", offset, buf.len());

        let extra = if offset + (len as u64) > vsize {
            // Clamp to the in-image portion: only `vsize - offset` bytes are
            // backed by data, rounded down to a block boundary.
            len = ((vsize - offset) as usize) & !bs_mask;
            if info.is_back_file() {
                buf.len() - len
            } else {
                0
            }
        } else {
            0
        };

        debug_assert!((len & bs_mask) == 0);

        let done = if single {
            let l2_entry = self.get_l2_entry(offset).await?;

            self.do_read(l2_entry, offset, buf).await?
        } else {
            let nr_clusters = (len >> info.cluster_bits()) + 2;
            let mut reads = Vec::with_capacity(nr_clusters);
            let mut lens = Vec::with_capacity(nr_clusters);
            let mut remain = buf;
            let mut idx = 0;
            let mut s = 0;
            let l2_entries = self.get_l2_entries(offset, len).await?;

            while len > 0 {
                let in_cluster_offset = info.in_cluster_offset(offset);
                let curr_len = std::cmp::min(info.cluster_size() - in_cluster_offset, len);
                let (iobuf, b) = remain.split_at_mut(curr_len);
                remain = b;

                reads.push(self.do_read(l2_entries[idx], offset, iobuf));
                lens.push(curr_len);

                offset += curr_len as u64;
                len -= curr_len;
                idx += 1;
            }

            let res = futures::future::join_all(reads).await;
            for (exp, r) in lens.into_iter().zip(res) {
                match r {
                    Ok(r) => {
                        s += r;
                        if r != exp {
                            break;
                        }
                    }
                    Err(_) => break,
                };
            }
            s
        };

        log::debug!(
            "read_at: offset {:x} len {} res {} <<<",
            old_offset,
            old_len,
            done
        );
        Ok(done + extra)
    }

    #[async_recursion(?Send)]
    async fn read_at_for_backing(&self, buf: &mut [u8], offset: u64) -> Qcow2Result<usize> {
        self.__read_at(buf, offset).await
    }

    /// Read data to `buf` from the virtual `offset` of this qcow2 image
    pub async fn read_at(&self, buf: &mut [u8], offset: u64) -> Qcow2Result<usize> {
        self.__read_at(buf, offset).await
    }
}
