//! Wire format version (`v<major>`, independent of binary semver).

use serde::{Deserialize, Serialize};

/// Wire format version: major only.
///
/// On the wire this is named `v<major>` and is independent of binary semver
/// (naming lock).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WireVersion {
    pub major: u16,
}

impl WireVersion {
    /// Current PoC wire version.
    pub const V1: Self = Self { major: 1 };

    /// Whether this major is accepted by this build.
    pub const fn is_supported(self) -> bool {
        self.major == Self::V1.major
    }
}

impl core::fmt::Display for WireVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "v{}", self.major)
    }
}
