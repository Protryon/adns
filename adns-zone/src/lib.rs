use adns_proto::{Class, Name, Question, Record, SoaData, Type, TypeData, TypeDataParseError};
use indexmap::{map::Entry, IndexMap};
use log::warn;
use serde::{ser::SerializeSeq, Deserialize, Serialize};
use serde_with::{serde_as, DeserializeAs, SerializeAs};

mod updates;
pub use updates::*;

struct VecRecordConvert;

impl SerializeAs<Vec<Record>> for VecRecordConvert {
    fn serialize_as<S: serde::Serializer>(
        source: &Vec<Record>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(source.len()))?;
        for item in source {
            let item: ZoneRecord = item.clone().into();
            seq.serialize_element(&item)?;
        }
        seq.end()
    }
}

impl<'de> DeserializeAs<'de, Vec<Record>> for VecRecordConvert {
    fn deserialize_as<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<Record>, D::Error> {
        let from = Vec::<ZoneRecord>::deserialize(deserializer)?;
        from.into_iter()
            .map(|x| -> Result<Record, _> { x.try_into() })
            .collect::<Result<Vec<Record>, TypeDataParseError>>()
            .map_err(serde::de::Error::custom)
    }
}

struct SubZoneConvert;

impl SerializeAs<IndexMap<Name, Zone>> for SubZoneConvert {
    fn serialize_as<S: serde::Serializer>(
        source: &IndexMap<Name, Zone>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        source
            .clone()
            .into_iter()
            .map(|x| (x.0, x.1.into()))
            .collect::<IndexMap<Name, SubZone>>()
            .serialize(serializer)
    }
}

impl<'de> DeserializeAs<'de, IndexMap<Name, Zone>> for SubZoneConvert {
    fn deserialize_as<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<IndexMap<Name, Zone>, D::Error> {
        let from = IndexMap::<Name, SubZone>::deserialize(deserializer)?;
        Ok(from.into_iter().map(|x| (x.0, x.1.into())).collect())
    }
}

fn serde_true() -> bool {
    true
}

fn serde_is_true(value: &bool) -> bool {
    *value
}

#[serde_as]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Zone {
    //todo: some kind of indexmap structure?
    #[serde_as(as = "VecRecordConvert")]
    #[serde(default)]
    pub records: Vec<Record>,
    #[serde(default)]
    #[serde_as(as = "SubZoneConvert")]
    pub zones: IndexMap<Name, Zone>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soa: Option<SoaData>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nameservers: Vec<Name>,
    #[serde(default)]
    pub tsig_keys: IndexMap<String, TsigKey>,
    #[serde(default = "serde_true", skip_serializing_if = "serde_is_true")]
    pub authoritative: bool,
    #[serde(skip)]
    pub class: Class,
    #[serde(default)]
    pub allow_md5_tsig: bool,
}

#[serde_as]
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct SubZone {
    //todo: some kind of indexmap structure?
    #[serde_as(as = "VecRecordConvert")]
    #[serde(default)]
    pub records: Vec<Record>,
    #[serde(default = "serde_true", skip_serializing_if = "serde_is_true")]
    pub authoritative: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soa: Option<SoaData>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nameservers: Vec<Name>,
}

impl From<SubZone> for Zone {
    fn from(value: SubZone) -> Self {
        Zone {
            records: value.records,
            zones: Default::default(),
            tsig_keys: Default::default(),
            authoritative: value.authoritative,
            class: Default::default(),
            allow_md5_tsig: Default::default(),
            soa: value.soa,
            nameservers: value.nameservers,
        }
    }
}

impl From<Zone> for SubZone {
    fn from(value: Zone) -> Self {
        SubZone {
            records: value.records,
            authoritative: value.authoritative,
            soa: value.soa,
            nameservers: value.nameservers,
        }
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TsigKey(#[serde_as(as = "serde_with::base64::Base64")] pub Vec<u8>);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnswerState {
    None,
    DomainSeen,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct ZoneAnswer {
    pub is_authoritative: bool,
    pub answers: Vec<Record>,
}

impl Zone {
    pub fn merge_from(&mut self, other: Zone) {
        for record in other.records {
            ZoneUpdateAction::AddRecord(record).apply_to(&Name::default(), self);
        }
        for (zone_name, new_zone) in other.zones {
            match self.zones.entry(zone_name.clone()) {
                Entry::Occupied(mut current_zone) => {
                    let current_zone = current_zone.get_mut();
                    for record in new_zone.records {
                        ZoneUpdateAction::AddRecord(record).apply_to(&zone_name, current_zone);
                    }
                }
                Entry::Vacant(v) => {
                    v.insert(new_zone);
                }
            }
        }
    }

    pub fn answer(
        &self,
        parent_zone: Option<&Zone>,
        zone_name: &Name,
        question: &Question,
        response: &mut ZoneAnswer,
    ) -> AnswerState {
        response.is_authoritative = self.authoritative;
        if &question.name == zone_name {
            match question.type_ {
                Type::SOA => {
                    if let Some(soa) = self
                        .soa
                        .clone()
                        .or_else(|| parent_zone.and_then(|x| x.soa.clone()))
                    {
                        response.answers.push(Record::new(
                            zone_name.clone(),
                            60,
                            TypeData::SOA(soa),
                        ));
                    } else {
                        warn!("no SOA specified for zone {}", zone_name);
                    }
                    return AnswerState::DomainSeen;
                }
                Type::NS => {
                    #[allow(clippy::unnecessary_unwrap)]
                    let nameservers = if self.nameservers.is_empty() && parent_zone.is_some() {
                        &parent_zone.unwrap().nameservers
                    } else {
                        &self.nameservers
                    };
                    for nameserver in nameservers {
                        response.answers.push(Record::new(
                            zone_name.clone(),
                            3600,
                            TypeData::NS(nameserver.clone()),
                        ));
                    }
                    return AnswerState::DomainSeen;
                }
                _ => (),
            }
        }
        let mut state = AnswerState::None;
        for record in &self.records {
            if !record.name.contains(&question.name) {
                continue;
            }
            state = AnswerState::DomainSeen;
            if !question.type_.wants_by_query(record.type_) {
                continue;
            }
            response.answers.push(Record {
                name: question.name.clone(),
                type_: record.type_,
                class: record.class,
                ttl: record.ttl,
                data: record.data.clone(),
            });
        }
        for (name, zone) in &self.zones {
            if !question.name.ends_with(name) {
                continue;
            }
            let substate = zone.answer(Some(self), name, question, response);
            if substate > state {
                state = substate;
            }
        }
        state
    }
}

fn default_ttl() -> u32 {
    300
}

fn is_default_ttl(value: &u32) -> bool {
    *value == 300
}

fn is_default_class(class: &Class) -> bool {
    *class == Class::IN
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ZoneRecord {
    domain: Name,
    #[serde(rename = "type")]
    type_: Type,
    #[serde(default, skip_serializing_if = "is_default_class")]
    class: Class,
    #[serde(default = "default_ttl", skip_serializing_if = "is_default_ttl")]
    ttl: u32,
    data: String,
}

impl TryInto<Record> for ZoneRecord {
    type Error = TypeDataParseError;

    fn try_into(self) -> Result<Record, Self::Error> {
        Ok(Record {
            name: self.domain,
            type_: self.type_,
            class: self.class,
            ttl: self.ttl,
            data: TypeData::parse_str(self.type_, &self.data)?,
        })
    }
}

impl From<Record> for ZoneRecord {
    fn from(value: Record) -> Self {
        ZoneRecord {
            domain: value.name.clone(),
            type_: value.type_,
            class: value.class,
            ttl: value.ttl,
            data: value.data.to_string(),
        }
    }
}
