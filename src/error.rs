// borrowed from rsd project

use std::io;

#[derive(Debug)]
pub struct Qcow2Error {
    description: String,
    io: io::Error,
}

pub type Qcow2Result<R> = Result<R, Qcow2Error>;

impl Clone for Qcow2Error {
    fn clone(&self) -> Self {
        Qcow2Error {
            description: self.description.clone(),
            io: io::Error::from(self.io.kind()),
        }
    }
}

#[cfg(not(target_os = "windows"))]
impl From<nix::errno::Errno> for Qcow2Error {
    fn from(err: nix::errno::Errno) -> Self {
        let description = err.to_string();
        Qcow2Error {
            description,
            io: err.into(),
        }
    }
}

impl From<io::Error> for Qcow2Error {
    fn from(err: io::Error) -> Self {
        let description = err.to_string();
        Qcow2Error {
            description,
            io: err,
        }
    }
}

impl From<io::ErrorKind> for Qcow2Error {
    fn from(err: io::ErrorKind) -> Self {
        let io = io::Error::from(err);
        let description = io.to_string();
        Qcow2Error { description, io }
    }
}

macro_rules! impl_from {
    ($type:ty, $kind:ident) => {
        impl From<$type> for Qcow2Error {
            fn from(err: $type) -> Self {
                let description = err.to_string();
                let io = io::Error::new(io::ErrorKind::$kind, description.clone());
                Qcow2Error { description, io }
            }
        }
    };
}

impl_from!(Box<bincode::ErrorKind>, InvalidData);
impl_from!(std::num::TryFromIntError, InvalidData);
impl_from!(std::str::Utf8Error, InvalidData);
impl_from!(&str, Other);
impl_from!(String, Other);
impl_from!(std::alloc::LayoutError, OutOfMemory);

impl Qcow2Error {
    pub fn from_desc(description: String) -> Self {
        let io = io::Error::new(io::ErrorKind::Other, description.clone());
        Qcow2Error { description, io }
    }

    pub fn into_inner(self) -> io::Error {
        self.io
    }

    pub fn get_inner(&self) -> &io::Error {
        &self.io
    }

    pub fn into_description(self) -> String {
        self.description
    }

    #[must_use]
    pub fn prepend(mut self, prefix: &str) -> Self {
        self.description = format!("{}: {}", prefix, self.description);
        self
    }
}

impl std::fmt::Display for Qcow2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description)
    }
}

impl std::error::Error for Qcow2Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qcow2_error_from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::Other, "test error");
        let qcow2_err = Qcow2Error::from(io_err);
        assert_eq!(qcow2_err.description, "test error");
        assert_eq!(qcow2_err.io.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn test_qcow2_error_from_io_error_kind() {
        let io_err_kind = io::ErrorKind::NotFound;
        let qcow2_err = Qcow2Error::from(io_err_kind);
        assert_eq!(qcow2_err.description, "entity not found");
        assert_eq!(qcow2_err.io.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn test_qcow2_error_from_box_bincode_error_kind() {
        let bincode_err_kind = bincode::ErrorKind::Custom("test error".to_string());
        let qcow2_err = Qcow2Error::from(Box::new(bincode_err_kind));
        assert_eq!(qcow2_err.description, "test error");
        assert_eq!(qcow2_err.io.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_qcow2_error_from_try_from_int_error() {
        let result: Result<u16, _> = 50000_i32.try_into();
        if let Err(e) = result {
            let qcow2_err = Qcow2Error::from(e);
            assert_eq!(
                qcow2_err.description,
                "out of range integral type conversion attempted"
            );
            assert_eq!(qcow2_err.io.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    #[rustversion::attr(since(1.74), allow(invalid_from_utf8))]
    fn test_qcow2_error_from_utf8_error() {
        let bytes = [0x80, 0x80];
        if let Err(e) = std::str::from_utf8(&bytes) {
            let qcow2_err = Qcow2Error::from(e);
            //assert_eq!(qcow2_err.description, "invalid utf-8 sequence of bytes");
            assert_eq!(qcow2_err.io.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn test_qcow2_error_from_str() {
        let str_err = "test error";
        let qcow2_err = Qcow2Error::from(str_err);
        assert_eq!(qcow2_err.description, "test error");
        assert_eq!(qcow2_err.io.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn test_qcow2_error_from_string() {
        let string_err = "test error".to_string();
        let qcow2_err = Qcow2Error::from(string_err);
        assert_eq!(qcow2_err.description, "test error");
        assert_eq!(qcow2_err.io.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn test_qcow2_error_from_layout_error() {
        if let Err(e) = std::alloc::Layout::from_size_align(1024, 0) {
            let qcow2_err = Qcow2Error::from(e);
            //assert_eq!(qcow2_err.description, "test error");
            assert_eq!(qcow2_err.io.kind(), io::ErrorKind::OutOfMemory);
        }
    }

    #[test]
    fn test_qcow2_error_from_desc() {
        let qcow2_err = Qcow2Error::from_desc("test error".to_string());
        assert_eq!(qcow2_err.description, "test error");
        assert_eq!(qcow2_err.io.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn test_qcow2_error_prepend() {
        let qcow2_err = Qcow2Error::from("test error");
        let new_err = qcow2_err.prepend("prefix");
        assert_eq!(new_err.description, "prefix: test error");
    }
}
