// These are helpers, do not issue a warning if not all of them are used because of some disabled
// features (and making all conditionally-used features conditional themselves is too cumbersome to
// be worth it).
#![allow(dead_code)]
use crate::error::Qcow2Result;
use core::future::Future;
use std::pin::Pin;

#[macro_export]
macro_rules! numerical_enum {
    (
        $(#[$attr:meta])*
        pub enum $enum_name:ident as $repr:tt {
            $(
                $(#[$id_attr:meta])*
                $identifier:ident = $value:literal,
            )+
        }
    ) => {
        $(#[$attr])*
        #[derive(Copy, Clone, Debug, Eq, PartialEq)]
        #[repr($repr)]
        pub enum $enum_name {
            $(
                $(#[$id_attr])*
                $identifier = $value,
            )+
        }

        impl TryFrom<$repr> for $enum_name {
            type Error = $crate::error::Qcow2Error;
            fn try_from(val: $repr) -> $crate::error::Qcow2Result<Self> {
                match val {
                    $($value => Ok($enum_name::$identifier),)*
                    _ => Err($crate::error::Qcow2Error::from_desc(format!(
                        "Invalid value for {}: {:x}",
                        stringify!($enum_name),
                        val
                    ))),
                }
            }
        }
    }
}

// TODO: Replace by int_roundings once that is stable
pub trait IntAlignment: Sized {
    /// Align `self` down to the closest value less or equal to `self` that is aligned to
    /// `alignment`.  Returns `None` if and only if there is no such value.
    /// `alignment` must be a power of two.
    fn align_down<T: Into<Self>>(self, alignment: T) -> Option<Self>;

    /// Align `self` up to the closest value greater or equal to `self` that is aligned to
    /// `alignment`.  Returns `None` if and only if there is no such value.
    /// `alignment` must be a power of two.
    fn align_up<T: Into<Self>>(self, alignment: T) -> Option<Self>;
}

macro_rules! impl_int_alignment_for_primitive {
    ($type:tt) => {
        impl IntAlignment for $type {
            fn align_down<T: Into<Self>>(self, alignment: T) -> Option<Self> {
                let alignment: Self = alignment.into();
                debug_assert!(alignment.is_power_of_two());

                Some(self & !(alignment - 1))
            }

            fn align_up<T: Into<Self>>(self, alignment: T) -> Option<Self> {
                let alignment: Self = alignment.into();
                debug_assert!(alignment.is_power_of_two());

                if self & (alignment - 1) == 0 {
                    return Some(self);
                }
                (self | (alignment - 1)).checked_add(1)
            }
        }
    };
}

impl_int_alignment_for_primitive!(u8);
impl_int_alignment_for_primitive!(u16);
impl_int_alignment_for_primitive!(u32);
impl_int_alignment_for_primitive!(u64);
impl_int_alignment_for_primitive!(usize);

pub type BoxedFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;
pub type Qcow2FutureResult<'a, T> = BoxedFuture<'a, Qcow2Result<T>>;

#[macro_export]
macro_rules! page_aligned_vec {
    ($type:ty, $size:expr) => {{
        #[repr(C, align(4096))]
        #[derive(Clone)]
        struct PageAlignedBuf([u8; 512]);

        let sz = ($size + 511) & !511;
        let nr = sz / 512;
        let buf = Vec::<PageAlignedBuf>::with_capacity(nr);
        unsafe {
            let mut a: Vec<$type> = std::mem::transmute(buf);
            a.set_len(sz / core::mem::size_of::<$type>());
            a
        }
    }};
}

/// It is user's responsibility to not free buffer of the slice
pub fn slice_to_vec<T>(s: &[T]) -> Vec<T> {
    // Get a pointer to the data and its length from the existing slice
    let ptr = s.as_ptr();
    let len = s.len();

    unsafe { Vec::from_raw_parts(ptr as *mut T, len, len) }
}

#[macro_export]
macro_rules! zero_buf {
    ($buffer:expr) => {{
        unsafe {
            std::ptr::write_bytes($buffer.as_mut_ptr(), 0, $buffer.len());
        }
    }};
}

pub fn qcow2_type_of<T>(_: &T) -> String {
    format!("{}", std::any::type_name::<T>())
}
