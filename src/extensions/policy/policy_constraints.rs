//! `PolicyConstraints` (id 28).
//! `PolicyConstraints` = [
//!     requireExplicitPolicy: uint / null,
//!     inhibitPolicyMapping: uint / null,
//!   ]

use minicbor::{Decoder, Encoder};
use serde::{Deserialize, Serialize};

use crate::common::{decode_opt_uint, encode_opt_uint, expect_array_len};
use crate::error::Result;

/// `PolicyConstraints` = [
///     requireExplicitPolicy: uint / null,
///     inhibitPolicyMapping: uint / null,
///   ]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyConstraints {
    /// The require explicit policy.
    pub require_explicit_policy: Option<u32>,
    /// The inhibit policy mapping.
    pub inhibit_policy_mapping: Option<u32>,
}

impl PolicyConstraints {
    /// Decode a `PolicyConstraints`.
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        expect_array_len(d, 2)?;
        let require_explicit_policy = decode_opt_uint(d)?;
        let inhibit_policy_mapping = decode_opt_uint(d)?;
        Ok(Self {
            require_explicit_policy,
            inhibit_policy_mapping,
        })
    }

    /// Encode a `PolicyConstraints`.
    pub(crate) fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        e.array(2)?;
        encode_opt_uint(e, self.require_explicit_policy)?;
        encode_opt_uint(e, self.inhibit_policy_mapping)?;
        Ok(())
    }
}
