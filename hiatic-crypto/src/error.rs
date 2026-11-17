use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    RandomnessUnavailable,
    KeyNotFound,
    KeyAlreadyExists,
    AuthenticationFailed,
    TransportFailed,
    ActorUnavailable,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RandomnessUnavailable => "secure randomness is unavailable",
            Self::KeyNotFound => "key was not found",
            Self::KeyAlreadyExists => "key already exists",
            Self::AuthenticationFailed => "authenticated decryption failed",
            Self::TransportFailed => "key transport failed",
            Self::ActorUnavailable => "wallet actor is unavailable",
        })
    }
}

impl std::error::Error for Error {}

impl From<getrandom::Error> for Error {
    fn from(_: getrandom::Error) -> Self {
        Self::RandomnessUnavailable
    }
}
