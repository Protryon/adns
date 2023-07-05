use std::fmt::Write;

use adns_proto::{Class, Packet, ResponseCode, Type, TypeData};
use adns_zone::{Zone, ZoneUpdate, ZoneUpdateAction};
use log::info;
use thiserror::Error;

use crate::metrics;

#[derive(Error, Debug)]
pub enum UpdateError {
    #[error("unexpected number of zones, expected 1")]
    BadZoneCount,
    #[error("malformed zone declaration (bad type or class)")]
    MalformedZone,
    #[error("an update record was not in the zone")]
    RecordNotZoned,
    #[error("prerequisite name not found")]
    NameNotFound,
    #[error("prerequisite rrset not found")]
    RRSetNotFound,
    #[error("format error")]
    FormatError,
    #[error("prerequisite name found")]
    NameFound,
    #[error("prerequisite rrset found")]
    RRSetFound,
}

fn do_respond_update(from: &str, zone: &Zone, packet: &Packet) -> Result<ZoneUpdate, UpdateError> {
    if packet.questions.len() != 1 {
        return Err(UpdateError::BadZoneCount);
    }
    let question = packet.questions.first().unwrap();
    if question.type_ != Type::SOA || question.class != zone.class {
        return Err(UpdateError::MalformedZone);
    }

    let mut zone_update = ZoneUpdate {
        zone_name: question.name.clone(),
        actions: vec![],
    };

    let tzone: Zone;
    let root_prefix = "**".parse().unwrap();
    let (zone_prefix, zone) = match question.name.as_ref() {
        "" => (&root_prefix, zone),
        _ => match zone.zones.get(&question.name) {
            Some(zone) => (&question.name, zone),
            None => {
                tzone = Zone::default();
                (&question.name, &tzone)
            }
        },
    };
    //TODO: zone name auth??

    let mut out = String::new();
    for prereq in &packet.answers {
        write!(
            &mut out,
            "\npre-> {} {} {} {}",
            prereq.name, prereq.class, prereq.type_, prereq.data
        )
        .unwrap();
    }
    for update in &packet.nameservers {
        write!(
            &mut out,
            "\nupdate-> {} {} {} {}",
            update.name, update.class, update.type_, update.data
        )
        .unwrap();
    }
    info!(
        "[{}]-{:04X} Update Zone '{}': {}",
        from, packet.header.id, question.name, out
    );

    // handle prereq
    let mut prereq_records = vec![];
    for prereq in &packet.answers {
        match (prereq.class, prereq.type_) {
            (Class::ALL, Type::ALL) => {
                if !zone.records.iter().any(|record| record.name == prereq.name) {
                    return Err(UpdateError::NameNotFound);
                }
            }
            (Class::ALL, type_) => {
                if !zone
                    .records
                    .iter()
                    .any(|record| record.name == prereq.name && record.type_ == type_)
                {
                    return Err(UpdateError::RRSetNotFound);
                }
            }
            (Class::NONE, Type::ALL) => {
                if zone.records.iter().any(|record| record.name == prereq.name) {
                    return Err(UpdateError::NameFound);
                }
            }
            (Class::NONE, type_) => {
                if zone
                    .records
                    .iter()
                    .any(|record| record.name == prereq.name && record.type_ == type_)
                {
                    return Err(UpdateError::RRSetFound);
                }
            }
            (class, _) if class == zone.class => {
                if prereq.ttl != 0 {
                    return Err(UpdateError::FormatError);
                }
                prereq_records.push((prereq.type_, &prereq.name, &prereq.data));
                continue;
            }
            _ => return Err(UpdateError::FormatError),
        }
        if prereq.ttl != 0 || prereq.data != TypeData::Other(prereq.type_, Default::default()) {
            return Err(UpdateError::FormatError);
        }
    }
    if !prereq_records.is_empty() {
        prereq_records.sort();
        let mut zone_records = zone
            .records
            .iter()
            .map(|x| (x.type_, &x.name, &x.data))
            .collect::<Vec<_>>();
        zone_records.sort();
        if prereq_records != zone_records {
            return Err(UpdateError::RRSetNotFound);
        }
    }

    // prereq passed

    // updates prescan
    for update in &packet.nameservers {
        if !update.name.ends_with(zone_prefix) {
            return Err(UpdateError::RecordNotZoned);
        }
        match update.class {
            c if c == zone.class => {
                if update.type_.is_question_type() {
                    return Err(UpdateError::FormatError);
                }
            }
            Class::ALL => {
                if update.ttl != 0
                    || update.data != TypeData::Other(update.type_, Default::default())
                    || (update.type_.is_question_type() && update.type_ != Type::ALL)
                {
                    return Err(UpdateError::FormatError);
                }
            }
            Class::NONE => {
                if update.ttl != 0 || update.type_.is_question_type() {
                    return Err(UpdateError::FormatError);
                }
            }
            _ => {
                return Err(UpdateError::FormatError);
            }
        }
    }

    let from_str = from.to_string();
    // do update
    for update in &packet.nameservers {
        metrics::UPDATES
            .with_label_values(&[
                &from_str,
                update.name.as_ref(),
                update.class.into(),
                update.type_.into(),
                "true",
            ])
            .inc();
        match update.class {
            c if c == zone.class => {
                zone_update
                    .actions
                    .push(ZoneUpdateAction::AddRecord(update.clone()));
            }
            Class::ALL => {
                let type_ = if update.type_ == Type::ALL {
                    None
                } else {
                    Some(update.type_)
                };
                zone_update
                    .actions
                    .push(ZoneUpdateAction::DeleteRecords(update.name.clone(), type_));
            }
            Class::NONE => {
                zone_update.actions.push(ZoneUpdateAction::DeleteRecord(
                    update.name.clone(),
                    update.data.clone(),
                ));
            }
            _ => {
                return Err(UpdateError::FormatError);
            }
        }
    }

    Ok(zone_update)
}

pub fn respond_update(
    from: &str,
    zone: &Zone,
    packet: &Packet,
    mut response: Packet,
) -> Result<(ZoneUpdate, Packet), Packet> {
    match do_respond_update(from, zone, packet) {
        Ok(x) => Ok((x, response)),
        Err(UpdateError::BadZoneCount)
        | Err(UpdateError::MalformedZone)
        | Err(UpdateError::FormatError)
        | Err(UpdateError::RecordNotZoned) => {
            response.header.response_code = ResponseCode::FormatError;
            Err(response)
        }
        Err(UpdateError::NameNotFound) => {
            response.header.response_code = ResponseCode::NameError;
            Err(response)
        }
        Err(UpdateError::RRSetNotFound) => {
            response.header.response_code = ResponseCode::NxRRSet;
            Err(response)
        }
        Err(UpdateError::NameFound) => {
            response.header.response_code = ResponseCode::YxDomain;
            Err(response)
        }
        Err(UpdateError::RRSetFound) => {
            response.header.response_code = ResponseCode::YxRRSet;
            Err(response)
        }
    }
}
