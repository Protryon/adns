#![allow(deprecated)]

use std::fmt;

use crate::{
    context::{DeserializeContext, SerializeContext},
    Class, Name, NameParseError, PacketParseError, Type,
};

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Question {
    pub name: Name,
    #[serde(rename = "type")]
    pub type_: Type,
    #[serde(default)]
    pub class: Class,
}

impl fmt::Display for Question {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.type_, self.name)
    }
}

impl Question {
    pub fn new(type_: Type, name: impl AsRef<str>) -> Result<Self, NameParseError> {
        Ok(Self {
            name: name.as_ref().parse()?,
            type_,
            class: Default::default(),
        })
    }

    pub(crate) fn parse(context: &mut DeserializeContext<'_>) -> Result<Self, PacketParseError> {
        Ok(Self {
            name: context.read_name()?,
            type_: context.read(u16::from_be_bytes)?.into(),
            class: context.read(u16::from_be_bytes)?.into(),
        })
    }

    pub(crate) fn serialize(&self, context: &mut SerializeContext) {
        context.write_name(&self.name);
        context.write_blob(<Type as Into<u16>>::into(self.type_).to_be_bytes());
        context.write_blob(<Class as Into<u16>>::into(self.class).to_be_bytes());
    }
}
