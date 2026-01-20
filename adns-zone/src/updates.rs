use adns_proto::{Name, Record, SoaData, Type, TypeData};

use crate::Zone;

pub struct ZoneUpdate {
    /// "" for root zone, "name" for 2nd level zone
    pub zone_name: Name,
    pub actions: Vec<ZoneUpdateAction>,
}

pub enum ZoneUpdateAction {
    DeleteRecords(Name, Option<Type>),
    DeleteRecord(Name, TypeData),
    AddRecord(Record),
}

impl ZoneUpdate {
    pub fn apply_to(&self, root_zone: &mut Zone) {
        let zone = if self.zone_name.is_empty() {
            root_zone
        } else {
            root_zone.zones.entry(self.zone_name.clone()).or_default()
        };
        for action in &self.actions {
            action.apply_to(&self.zone_name, zone);
        }
    }
}

impl ZoneUpdateAction {
    pub fn apply_to(&self, zone_name: &Name, zone: &mut Zone) {
        match self {
            ZoneUpdateAction::DeleteRecords(name, None) => {
                if name == zone_name {
                    zone.records.retain(|record| {
                        &record.name != name
                            || record.type_ == Type::SOA
                            || record.type_ == Type::NS
                    });
                } else {
                    zone.records.retain(|record| &record.name != name);
                }
            }
            ZoneUpdateAction::DeleteRecords(name, Some(type_)) => {
                if name == zone_name && (*type_ == Type::SOA || *type_ == Type::NS) {
                    return;
                }
                zone.records
                    .retain(|record| &record.name != name || record.type_ != *type_);
            }
            ZoneUpdateAction::DeleteRecord(name, data) => {
                if name == zone_name
                    && (data.dns_type() == Type::SOA
                        || (data.dns_type() == Type::NS
                            && zone.records.iter().filter(|x| x.type_ == Type::NS).count() <= 1))
                {
                    return;
                }
                zone.records.retain(|record| {
                    &record.name != name || record.type_ != data.dns_type() || &record.data != data
                });
            }
            ZoneUpdateAction::AddRecord(record) => {
                let mut record = record.clone();
                record.ttl = record.ttl.max(60);
                if record.type_ == Type::CNAME {
                    if zone.records.len() > 1
                        || zone
                            .records
                            .first()
                            .map(|x| x.type_ != Type::CNAME)
                            .unwrap_or_default()
                    {
                        return;
                    }
                } else if zone.records.iter().any(|x| x.type_ == Type::CNAME) {
                    return;
                }
                if record.type_ == Type::SOA {
                    let Record {
                        data:
                            TypeData::SOA(SoaData {
                                serial: new_serial, ..
                            }),
                        ..
                    } = &record
                    else {
                        return;
                    };
                    if let Some(Record {
                        data: TypeData::SOA(SoaData { serial, .. }),
                        ..
                    }) = zone
                        .records
                        .iter()
                        .find(|x| x.name == record.name && x.type_ == Type::SOA)
                    {
                        if serial > new_serial {
                            return;
                        }
                    }
                }
                for zone_record in zone.records.iter_mut().filter(|zone_record| {
                    zone_record.name == record.name && zone_record.type_ == record.type_
                }) {
                    if record.type_ == Type::CNAME
                        || record.type_ == Type::SOA
                        || record.data == zone_record.data
                    {
                        *zone_record = record;
                        return;
                    }
                }
                zone.records.push(record);
            }
        }
    }
}
