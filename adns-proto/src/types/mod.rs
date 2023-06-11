// needed due to some issue in strum
#![allow(deprecated)]

use strum::FromRepr;

mod data;
pub use data::*;

mod data_parser;
pub use data_parser::*;

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    Debug,
    FromRepr,
    strum::Display,
    strum::EnumString,
    PartialOrd,
    Ord,
    strum::IntoStaticStr,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u16)]
pub enum Type {
    A = 1,
    NS,
    #[deprecated]
    MD,
    #[deprecated]
    MF,
    CNAME,
    SOA,
    #[deprecated]
    MB,
    #[deprecated]
    MG,
    #[deprecated]
    MR,
    #[deprecated]
    NULL,
    #[deprecated]
    WKS,
    PTR,
    HINFO,
    #[deprecated]
    MINFO,
    MX,
    TXT,
    RP,
    AFSDB,

    SIG = 24,
    KEY,

    AAAA = 28,
    LOC,

    SRV = 33,

    NAPTR = 35,
    KX,
    CERT,

    DNAME = 39,

    // EDNS
    OPT = 41,

    APL = 42,
    DS,
    SSHFP,
    IPSECKEY,
    RRSIG,
    NSEC,
    DNSKEY,
    DHCID,
    NSEC3,
    NSEC3PARAM,
    TLSA,
    SMIMEA,

    HIP = 55,

    CDS = 59,
    CDNSKEY,
    OPENPGPKEY,
    CSYNC,
    ZONEMD,
    SVCB,
    HTTPS,

    EUI48 = 108,
    EUI64,

    TKEY = 249,
    TSIG,

    // question types
    IXFR,
    AXFR,
    #[deprecated]
    MAILB,
    #[deprecated]
    MAILA,
    #[strum(to_string = "*")]
    ALL,

    URI = 256,
    CAA,

    TA = 32768,
    DLV,

    Other(u16),
}

impl From<u16> for Type {
    fn from(value: u16) -> Self {
        if let Some(out) = Type::from_repr(value) {
            if out != Type::Other(0) {
                return out;
            }
        }
        Type::Other(value)
    }
}

impl Type {
    fn discriminant(&self) -> u16 {
        unsafe { *(self as *const Self as *const u16) }
    }

    pub fn is_question_type(&self) -> bool {
        *self >= Type::IXFR && *self <= Type::ALL
    }

    pub fn wants_by_query(&self, other: Type) -> bool {
        *self == other
    }
}

impl From<Type> for u16 {
    fn from(value: Type) -> Self {
        match value {
            Type::Other(x) => x,
            x => x.discriminant(),
        }
    }
}
