use std::io;
use trackable::error::{ErrorKind as TrackableErrorKind, ErrorKindExt};
use trackable::error::{IntoTrackableError, TrackableError};

pub type Error = TrackableError<ErrorKind>;

#[derive(Debug, Clone)]
pub enum ErrorKind {
    Unsupported,
    Invalid,
    Other,
}
impl TrackableErrorKind for ErrorKind {}
impl IntoTrackableError<io::Error> for ErrorKind {
    fn into_trackable_error(from: io::Error) -> Error {
        ErrorKind::Other.cause(from)
    }
}
