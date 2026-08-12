use core::fmt;

/// An ASN.1 object identifier.
///
/// C509 represents OIDs in "unwrapped" form (CDDL `~oid`): the CBOR item is
/// a plain byte string containing the same content octets as a DER
/// `OBJECT IDENTIFIER` (i.e. the base-128 encoded arcs, without the DER
/// tag/length header and without the CBOR OID tag defined in RFC 9090).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Oid(Vec<u8>);

impl Oid {
    pub fn new(content_octets: Vec<u8>) -> Self {
        Oid(content_octets)
    }

    /// The raw DER content octets (base-128 arc encoding) of this OID.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Decode the dotted-decimal arcs, e.g. `[1, 2, 840, 113549, 1, 1, 1]`.
    ///
    /// Returns `None` if the byte string is not a valid base-128 VLQ OID
    /// encoding.
    pub fn arcs(&self) -> Option<Vec<u64>> {
        if self.0.is_empty() {
            return None;
        }
        let mut arcs = Vec::new();
        let mut value: u64 = 0;
        let mut first = true;
        let mut have_bits = false;
        for &byte in &self.0 {
            value = value.checked_shl(7)?.checked_add((byte & 0x7f) as u64)?;
            have_bits = true;
            if byte & 0x80 == 0 {
                if first {
                    let (a1, a2) = if value < 40 {
                        (0, value)
                    } else if value < 80 {
                        (1, value - 40)
                    } else {
                        (2, value - 80)
                    };
                    arcs.push(a1);
                    arcs.push(a2);
                    first = false;
                } else {
                    arcs.push(value);
                }
                value = 0;
                have_bits = false;
            }
        }
        if have_bits {
            // Truncated multi-byte VLQ sequence.
            return None;
        }
        Some(arcs)
    }
}

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Oid({self})")
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.arcs() {
            Some(arcs) => {
                for (i, arc) in arcs.iter().enumerate() {
                    if i > 0 {
                        f.write_str(".")?;
                    }
                    write!(f, "{arc}")?;
                }
                Ok(())
            }
            None => write!(f, "<invalid-oid:{:02x?}>", self.0),
        }
    }
}

impl<'b, C> minicbor::Decode<'b, C> for Oid {
    fn decode(d: &mut minicbor::Decoder<'b>, _ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        Ok(Oid(d.bytes()?.to_vec()))
    }
}

impl<C> minicbor::Encode<C> for Oid {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.bytes(&self.0)?;
        Ok(())
    }
}
