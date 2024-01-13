use crate::dev::{Qcow2Dev, Qcow2DevParams};
use crate::error::Qcow2Result;
use crate::meta::Qcow2Header;
use crate::ops::*;
use crate::page_aligned_vec;
use crate::sync_io::Qcow2IoSync;
use crate::uring::Qcow2IoUring;
use async_recursion::async_recursion;
use std::path::PathBuf;

#[macro_export]
macro_rules! qcow2_default_params {
    ($ro: expr, $dio: expr) => {
        Qcow2DevParams::new(9, None, None, $ro, $dio)
    };
}

pub fn qcow2_alloc_dev_sync<T: Qcow2IoOps>(
    path: &PathBuf,
    io: T,
    params: &Qcow2DevParams,
) -> Qcow2Result<(Qcow2Dev<T>, Option<PathBuf>)> {
    let mut buf = page_aligned_vec!(u8, 4096);
    {
        use std::io::Read;
        let mut file = std::fs::File::open(path).unwrap();
        file.read(&mut buf).unwrap();
    }
    let header = Qcow2Header::from_buf(&buf)?;
    let back_path = match header.backing_filename() {
        None => None,
        Some(s) => Some(PathBuf::from(s.clone())),
    };

    Ok((
        Qcow2Dev::new(path, header, params, io).expect("new dev failed"),
        back_path,
    ))
}

pub async fn qcow2_alloc_dev<T: Qcow2IoOps>(
    path: &PathBuf,
    io: T,
    params: &Qcow2DevParams,
) -> Qcow2Result<(Qcow2Dev<T>, Option<PathBuf>)> {
    let mut buf = page_aligned_vec!(u8, 4096);
    let _ = io.read_to(0, &mut buf).await;
    let header = Qcow2Header::from_buf(&buf)?;
    let back_path = match header.backing_filename() {
        None => None,
        Some(s) => Some(PathBuf::from(s.clone())),
    };

    Ok((
        Qcow2Dev::new(path, header, params, io).expect("new dev failed"),
        back_path,
    ))
}

/// Setup qcow2 device from `path`
///
/// TODO: need to be more generic for covering other IO engine, maybe one macro,
/// or trait trick

#[macro_export]
macro_rules! qcow2_setup_dev_fn {
    ($type:ty, $fn_name: ident) => {
        #[async_recursion(?Send)]
        pub async fn $fn_name(
            path: &PathBuf,
            params: &Qcow2DevParams,
        ) -> Qcow2Result<Qcow2Dev<$type>> {
            let io = <$type>::new(path, params.is_read_only(), params.is_direct_io()).await;
            let (mut dev, backing) = qcow2_alloc_dev(&path, io, params).await?;
            match backing {
                Some(back_path) => {
                    let p = params.clone();
                    p.mark_backing_dev(Some(true));
                    let bdev = $fn_name(&back_path, &p).await?;
                    dev.set_backing_dev(Box::new(bdev));
                }
                _ => {}
            };

            dev.__qcow2_prep_io().await?;
            Ok(dev)
        }
    };
}

qcow2_setup_dev_fn!(Qcow2IoUring, qcow2_setup_dev_uring);
qcow2_setup_dev_fn!(crate::tokio_io::Qcow2IoTokio, qcow2_setup_dev_tokio);

#[macro_export]
macro_rules! qcow2_setup_dev_fn_sync {
    ($type:ty, $fn_name: ident) => {
        pub fn $fn_name(path: &PathBuf, params: &Qcow2DevParams) -> Qcow2Result<Qcow2Dev<$type>> {
            let io = <$type>::new(path, params.is_read_only(), params.is_direct_io());
            let (mut dev, backing) = qcow2_alloc_dev_sync(&path, io, params)?;
            match backing {
                Some(back_path) => {
                    let p = params.clone();
                    p.mark_backing_dev(Some(true));
                    let bdev = $fn_name(&back_path, &p)?;
                    dev.set_backing_dev(Box::new(bdev));
                }
                _ => {}
            };

            Ok(dev)
        }
    };
}

qcow2_setup_dev_fn_sync!(Qcow2IoSync, qcow2_setup_dev_sync);
