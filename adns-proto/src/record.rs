use std::fmt;

use crate::{
    context::{DeserializeContext, SerializeContext},
    Name, PacketParseError, Type, TypeData,
};

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Record {
    #[serde(rename = "domain")]
    pub name: Name,
    #[serde(rename = "type")]
    pub type_: Type,
    pub class: Class,
    pub ttl: u32,
    pub data: TypeData,
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {} {}", self.name, self.type_, self.ttl, self.data)
    }
}

impl Record {
    pub fn new(name: Name, ttl: u32, data: TypeData) -> Self {
        Self {
            name,
            type_: data.dns_type(),
            class: Class::IN,
            ttl,
            data,
        }
    }

    pub(crate) fn parse(context: &mut DeserializeContext<'_>) -> Result<Self, PacketParseError> {
        let name = context.read_name()?;
        let type_ = context.read(u16::from_be_bytes)?.into();
        Ok(Self {
            name,
            type_,
            class: context.read(u16::from_be_bytes)?.into(),
            ttl: context.read(u32::from_be_bytes)?,
            data: {
                let length = context.read(u16::from_be_bytes)?;
                context.restrict(length as usize, |context| {
                    Ok(TypeData::parse_infallible(context, type_))
                })?
            },
        })
    }

    pub(crate) fn serialize(&self, context: &mut SerializeContext) {
        context.write_name(&self.name);
        context.write_blob(<Type as Into<u16>>::into(self.type_).to_be_bytes());
        context.write_blob(<Class as Into<u16>>::into(self.class).to_be_bytes());
        context.write_blob(self.ttl.to_be_bytes());
        context.capture_len_u16(|context| {
            self.data.serialize(context);
        });
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, strum::IntoStaticStr, strum::EnumString)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u16)]
pub enum Class {
    #[default]
    IN = 1,
    // CS,
    // CH,
    // HS,
    NONE = 254,
    ALL = 255,
    Other(u16),
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Class::IN => write!(f, "IN"),
            Class::NONE => write!(f, "NONE"),
            Class::ALL => write!(f, "ALL"),
            Class::Other(class) => write!(f, "CLASS{class:03}"),
        }
    }
}

impl From<u16> for Class {
    fn from(value: u16) -> Self {
        match value {
            1 => Class::IN,
            254 => Class::NONE,
            255 => Class::ALL,
            _ => Class::Other(value),
        }
    }
}

impl From<Class> for u16 {
    fn from(value: Class) -> Self {
        match value {
            Class::IN => 1,
            Class::NONE => 254,
            Class::ALL => 255,
            Class::Other(x) => x,
        }
    }
}
