use std::net::{Ipv4Addr, Ipv6Addr};

use smallvec::{smallvec, SmallVec};

use crate::{
    context::{DeserializeContext, SerializeContext},
    Name, PacketParseError, Type,
};

#[derive(Clone, PartialEq, Eq, Debug, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TypeData {
    A(Ipv4Addr),
    NS(Name),
    CNAME(Name),
    SOA(SoaData),
    PTR(Name),
    HINFO {
        cpu: String,
        os: String,
    },
    MX {
        preference: u16,
        exchange: Name,
    },
    /// while in theory, each argument here can be nul-terminated, in practice, most readers dont support it
    TXT(SmallVec<[String; 1]>),

    AAAA(Ipv6Addr),
    LOC {
        version: u8,
        size: u8,
        horiz_pre: u8,
        vert_pre: u8,
        latitude: i32,
        longitude: i32,
        altitude: i32,
    },

    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: Name,
    },

    CERT {
        type_: u16,
        key_tag: u16,
        algorithm: u8,
        data: Vec<u8>,
    },

    DNAME(Name),

    SSHFP {
        algorithm: u8,
        fp_type: u8,
        fingerprint: Vec<u8>,
    },

    TSIG(TsigData),

    URI {
        priority: u16,
        weight: u16,
        target: String,
    },

    Other(Type, SmallVec<[u8; 32]>),
}

#[derive(Clone, PartialEq, Eq, Debug, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SoaData {
    pub mname: Name,
    pub rname: Name,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

#[derive(Clone, PartialEq, Eq, Debug, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TsigData {
    pub algorithm: Name,
    pub time_signed: u64, // only a u48
    pub fudge: u16,
    pub mac: Vec<u8>,
    pub original_id: u16,
    pub error: TsigResponseCode,
    pub other_data: Vec<u8>,
}

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum TsigResponseCode {
    #[default]
    NoError,
    BadSig,
    BadKey,
    BadTime,
    Other(u16),
}

impl From<u16> for TsigResponseCode {
    fn from(value: u16) -> Self {
        match value {
            0 => TsigResponseCode::NoError,
            16 => TsigResponseCode::BadSig,
            17 => TsigResponseCode::BadKey,
            18 => TsigResponseCode::BadTime,
            _ => TsigResponseCode::Other(value),
        }
    }
}

impl From<TsigResponseCode> for u16 {
    fn from(value: TsigResponseCode) -> Self {
        match value {
            TsigResponseCode::NoError => 0,
            TsigResponseCode::BadSig => 16,
            TsigResponseCode::BadKey => 17,
            TsigResponseCode::BadTime => 18,
            TsigResponseCode::Other(x) => x,
        }
    }
}

impl TypeData {
    pub fn dns_type(&self) -> Type {
        match self {
            TypeData::A(..) => Type::A,
            TypeData::NS(..) => Type::NS,
            TypeData::CNAME(..) => Type::CNAME,
            TypeData::SOA { .. } => Type::SOA,
            TypeData::PTR(..) => Type::PTR,
            TypeData::HINFO { .. } => Type::HINFO,
            TypeData::MX { .. } => Type::MX,
            TypeData::TXT(..) => Type::TXT,
            TypeData::AAAA(..) => Type::AAAA,
            TypeData::LOC { .. } => Type::LOC,
            TypeData::SRV { .. } => Type::SRV,
            TypeData::CERT { .. } => Type::CERT,
            TypeData::DNAME(..) => Type::DNAME,
            TypeData::SSHFP { .. } => Type::SSHFP,
            TypeData::TSIG { .. } => Type::TSIG,
            TypeData::URI { .. } => Type::URI,
            TypeData::Other(type_, ..) => *type_,
        }
    }

    pub(crate) fn serialize(&self, context: &mut SerializeContext) {
        match self {
            TypeData::A(x) => context.write_blob(x.octets()),
            TypeData::DNAME(x) | TypeData::NS(x) | TypeData::CNAME(x) | TypeData::PTR(x) => {
                context.write_name(x)
            }
            TypeData::SOA(SoaData {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            }) => {
                context.write_name(mname);
                context.write_name(rname);
                context.write_blob(serial.to_be_bytes());
                context.write_blob(refresh.to_be_bytes());
                context.write_blob(retry.to_be_bytes());
                context.write_blob(expire.to_be_bytes());
                context.write_blob(minimum.to_be_bytes());
            }
            TypeData::HINFO { cpu, os } => {
                context.write_cstring(cpu);
                context.write_cstring(os);
            }
            TypeData::MX {
                preference,
                exchange,
            } => {
                context.write_blob(preference.to_be_bytes());
                context.write_name(exchange);
            }
            TypeData::TXT(texts) => {
                for text in texts {
                    context.write_cstring(text);
                }
            }
            TypeData::AAAA(x) => context.write_blob(x.octets()),
            TypeData::LOC {
                version,
                size,
                horiz_pre,
                vert_pre,
                latitude,
                longitude,
                altitude,
            } => {
                context.write_blob(version.to_be_bytes());
                context.write_blob(size.to_be_bytes());
                context.write_blob(horiz_pre.to_be_bytes());
                context.write_blob(vert_pre.to_be_bytes());
                context.write_blob(latitude.to_be_bytes());
                context.write_blob(longitude.to_be_bytes());
                context.write_blob(altitude.to_be_bytes());
            }
            TypeData::SRV {
                priority,
                weight,
                port,
                target,
            } => {
                context.write_blob(priority.to_be_bytes());
                context.write_blob(weight.to_be_bytes());
                context.write_blob(port.to_be_bytes());
                context.write_name(target);
            }
            TypeData::CERT {
                type_,
                key_tag,
                algorithm,
                data,
            } => {
                context.write_blob(type_.to_be_bytes());
                context.write_blob(key_tag.to_be_bytes());
                context.write_blob(algorithm.to_be_bytes());
                context.write_blob(data);
            }
            TypeData::SSHFP {
                algorithm,
                fp_type,
                fingerprint,
            } => {
                context.write_blob(algorithm.to_be_bytes());
                context.write_blob(fp_type.to_be_bytes());
                context.write_blob(fingerprint);
            }
            TypeData::TSIG(TsigData {
                algorithm,
                time_signed,
                fudge,
                mac,
                original_id,
                error,
                other_data,
            }) => {
                context.write_name(algorithm);
                context.write_blob(&time_signed.to_be_bytes()[2..8]);
                context.write_blob(fudge.to_be_bytes());
                context.write_blob((mac.len() as u16).to_be_bytes());
                context.write_blob(mac);
                context.write_blob(original_id.to_be_bytes());
                context.write_blob(<TsigResponseCode as Into<u16>>::into(*error).to_be_bytes());
                context.write_blob((other_data.len() as u16).to_be_bytes());
                context.write_blob(other_data);
            }
            TypeData::URI {
                priority,
                weight,
                target,
            } => {
                context.write_blob(priority.to_be_bytes());
                context.write_blob(weight.to_be_bytes());
                context.write_blob(target);
            }
            TypeData::Other(_, x) => context.write_blob(x),
        }
    }

    pub(crate) fn parse_infallible(context: &mut DeserializeContext<'_>, type_: Type) -> Self {
        context
            .attempt(|context| Self::parse(context, type_).ok())
            .unwrap_or_else(|| Self::Other(type_, Default::default()))
    }

    pub(crate) fn parse(
        context: &mut DeserializeContext<'_>,
        type_: Type,
    ) -> Result<Self, PacketParseError> {
        Ok(match type_ {
            Type::A => TypeData::A(context.read(<Ipv4Addr as From<[u8; 4]>>::from)?),
            Type::NS => TypeData::NS(context.read_name()?),
            Type::CNAME => TypeData::CNAME(context.read_name()?),
            Type::SOA => TypeData::SOA(SoaData {
                mname: context.read_name()?,
                rname: context.read_name()?,
                serial: context.read(u32::from_be_bytes)?,
                refresh: context.read(u32::from_be_bytes)?,
                retry: context.read(u32::from_be_bytes)?,
                expire: context.read(u32::from_be_bytes)?,
                minimum: context.read(u32::from_be_bytes)?,
            }),
            Type::PTR => TypeData::PTR(context.read_name()?),
            Type::HINFO => TypeData::HINFO {
                cpu: context.read_cstring()?,
                os: context.read_cstring()?,
            },
            Type::MX => TypeData::MX {
                preference: context.read(u16::from_be_bytes)?,
                exchange: context.read_name()?,
            },
            Type::TXT => {
                let mut out = smallvec![];
                while context.remaining() > 0 {
                    out.push(context.read_cstring()?);
                }
                TypeData::TXT(out)
            }
            Type::AAAA => TypeData::AAAA(context.read(<Ipv6Addr as From<[u8; 16]>>::from)?),
            Type::LOC => TypeData::LOC {
                version: context.read_u8()?,
                size: context.read_u8()?,
                horiz_pre: context.read_u8()?,
                vert_pre: context.read_u8()?,
                latitude: context.read(i32::from_be_bytes)?,
                longitude: context.read(i32::from_be_bytes)?,
                altitude: context.read(i32::from_be_bytes)?,
            },
            Type::SRV => TypeData::SRV {
                priority: context.read(u16::from_be_bytes)?,
                weight: context.read(u16::from_be_bytes)?,
                port: context.read(u16::from_be_bytes)?,
                target: context.read_name()?,
            },
            Type::CERT => TypeData::CERT {
                type_: context.read(u16::from_be_bytes)?,
                key_tag: context.read(u16::from_be_bytes)?,
                algorithm: context.read_u8()?,
                data: {
                    let mut out = vec![0u8; context.remaining()];
                    context.read_all(&mut out)?;
                    out
                },
            },
            Type::DNAME => TypeData::DNAME(context.read_name()?),
            Type::SSHFP => TypeData::SSHFP {
                algorithm: context.read_u8()?,
                fp_type: context.read_u8()?,
                fingerprint: {
                    let mut out = vec![0u8; context.remaining()];
                    context.read_all(&mut out)?;
                    out
                },
            },
            Type::TSIG => TypeData::TSIG(TsigData {
                algorithm: context.read_name()?,
                time_signed: {
                    let [a, b, c, d, e, f] = context.read_n::<6>()?;
                    u64::from_be_bytes([0, 0, a, b, c, d, e, f])
                },
                fudge: context.read(u16::from_be_bytes)?,
                mac: {
                    let len = context.read(u16::from_be_bytes)?;
                    let mut out = vec![0u8; len as usize];
                    context.read_all(&mut out)?;
                    out
                },
                original_id: context.read(u16::from_be_bytes)?,
                error: context.read(u16::from_be_bytes)?.into(),
                other_data: {
                    if context.remaining() == 0 {
                        vec![]
                    } else {
                        let len = context.read(u16::from_be_bytes)?;
                        let mut out = vec![0u8; len as usize];
                        context.read_all(&mut out)?;
                        out
                    }
                },
            }),
            Type::URI => TypeData::URI {
                priority: context.read(u16::from_be_bytes)?,
                weight: context.read(u16::from_be_bytes)?,
                target: {
                    let mut out = vec![0u8; context.remaining()];
                    context.read_all(&mut out)?;
                    String::from_utf8(out).map_err(|e| e.utf8_error())?
                },
            },
            type_ => {
                let mut all = smallvec![0u8; context.remaining()];
                context.read_all(&mut all)?;
                TypeData::Other(type_, all)
            }
        })
    }
}
