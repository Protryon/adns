use std::collections::HashMap;

use adns_proto::{Class, Name, Record, SoaData, Type, TypeData};
use adns_zone::{TsigKey, Zone, ZoneUpdate, ZoneUpdateAction};
use base64::{engine::general_purpose, Engine};
use log::error;
use tokio_postgres::{IsolationLevel, Row};
use uuid::Uuid;

use super::{Conn, PostgresError};

struct DbZone {
    id: Uuid,
    domain: Name,
    authoritative: bool,
    allow_md5_tsig: bool,
}

impl TryFrom<Row> for DbZone {
    type Error = PostgresError;

    fn try_from(row: Row) -> Result<Self, PostgresError> {
        Ok(Self {
            id: row.get(0),
            domain: row.get::<_, String>(1).parse()?,
            authoritative: row.get(2),
            allow_md5_tsig: row.get(3),
        })
    }
}

impl DbZone {
    pub async fn save(&self, conn: &Conn) -> Result<(), PostgresError> {
        conn.execute(r"INSERT INTO zones (id, domain, authoritative, allow_md5_tsig) VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO UPDATE SET
            domain = EXCLUDED.domain,
            authoritative = EXCLUDED.authoritative,
            allow_md5_tsig = EXCLUDED.allow_md5_tsig", &[&self.id, &self.domain.as_ref(), &self.authoritative, &self.allow_md5_tsig]).await?;
        Ok(())
    }
}

struct ZoneSoa {
    id: Uuid,
    soa: SoaData,
}

impl TryFrom<Row> for ZoneSoa {
    type Error = PostgresError;

    fn try_from(row: Row) -> Result<Self, PostgresError> {
        Ok(Self {
            id: row.get(0),
            soa: SoaData {
                mname: row.get::<_, String>(1).parse()?,
                rname: row.get::<_, String>(2).parse()?,
                serial: row.get::<_, i32>(3) as u32,
                refresh: row.get::<_, i32>(4) as u32,
                retry: row.get::<_, i32>(5) as u32,
                expire: row.get::<_, i32>(6) as u32,
                minimum: row.get::<_, i32>(7) as u32,
            },
        })
    }
}

struct ZoneNameserver {
    id: Uuid,
    #[allow(dead_code)]
    zone_id: Uuid,
    name: Name,
}

impl TryFrom<Row> for ZoneNameserver {
    type Error = PostgresError;

    fn try_from(row: Row) -> Result<Self, PostgresError> {
        Ok(Self {
            id: row.get(0),
            zone_id: row.get(1),
            name: row.get::<_, String>(2).parse()?,
        })
    }
}

struct ZoneTsigKey {
    #[allow(dead_code)]
    id: Uuid,
    zone_id: Uuid,
    name: String,
    keydata: Vec<u8>,
}

impl TryFrom<Row> for ZoneTsigKey {
    type Error = PostgresError;

    fn try_from(row: Row) -> Result<Self, PostgresError> {
        Ok(Self {
            id: row.get(0),
            zone_id: row.get(1),
            name: row.get(2),
            keydata: general_purpose::STANDARD_NO_PAD.decode(&row.get::<_, String>(3))?,
        })
    }
}

struct ZoneRecord {
    zone_id: Uuid,
    ordering: i32,
    name: Name,
    dns_type: Type,
    ttl: u32,
    data: TypeData,
}

impl TryFrom<Row> for ZoneRecord {
    type Error = PostgresError;

    fn try_from(row: Row) -> Result<Self, PostgresError> {
        let dns_type: Type = row.get::<_, String>(3).parse()?;
        Ok(Self {
            zone_id: row.get(0),
            ordering: row.get(1),
            name: row.get::<_, String>(2).parse()?,
            dns_type,
            ttl: row.get::<_, i32>(4) as u32,
            data: TypeData::parse_str(dns_type, &row.get::<_, String>(5))?,
        })
    }
}

impl ZoneRecord {
    pub async fn save(&self, conn: &Conn) -> Result<(), PostgresError> {
        let type_str: &'static str = self.dns_type.into();
        conn.execute(r"INSERT INTO zone_records (zone_id, ordering, name, dns_type, ttl, data) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (zone_id, ordering) DO UPDATE SET
            name = EXCLUDED.name,
            dns_type = EXCLUDED.dns_type,
            ttl = EXCLUDED.ttl,
            data = EXCLUDED.data", &[&self.zone_id, &self.ordering, &self.name.as_ref(), &type_str, &(self.ttl as i32), &self.data.to_string()]).await?;
        Ok(())
    }

    pub async fn insert_next_order(&self, conn: &Conn) -> Result<(), PostgresError> {
        let type_str: &'static str = self.dns_type.into();
        conn.execute(r"INSERT INTO zone_records (zone_id, ordering, name, dns_type, ttl, data) VALUES ($1, (SELECT coalesce(max(ordering), 0) FROM zone_records WHERE zone_id = $1) + 1, $2, $3, $4, $5)", &[&self.zone_id, &self.name.as_ref(), &type_str, &(self.ttl as i32), &self.data.to_string()]).await?;
        Ok(())
    }
}

pub async fn load_current_zone(conn: &mut Conn) -> Result<Zone, PostgresError> {
    let txn = conn
        .build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .await?;
    let conn = txn.client();
    let mut zones = conn
        .query(r"SELECT * FROM zones", &[])
        .await?
        .into_iter()
        .flat_map(|row| {
            let row: Result<DbZone, _> = row.try_into();
            match row {
                Ok(x) => Some((
                    x.id,
                    (
                        Zone {
                            records: vec![],
                            zones: Default::default(),
                            soa: None,
                            nameservers: vec![],
                            tsig_keys: Default::default(),
                            authoritative: x.authoritative,
                            class: Class::IN,
                            allow_md5_tsig: x.allow_md5_tsig,
                        },
                        x,
                    ),
                )),
                Err(e) => {
                    error!("failed to load zone from database, skipping: {e}");
                    None
                }
            }
        })
        .collect::<HashMap<Uuid, (Zone, DbZone)>>();
    for zone_soa in conn.query(r"SELECT * FROM zone_soas", &[]).await? {
        let zone_soa: Result<ZoneSoa, _> = zone_soa.try_into();
        match zone_soa {
            Ok(x) => {
                if let Some(zone) = zones.get_mut(&x.id) {
                    zone.0.soa = Some(x.soa);
                }
            }
            Err(e) => {
                error!("failed to parse zone SOA: {e}");
            }
        }
    }
    for zone_nameserver in conn.query(r"SELECT * FROM zone_nameservers", &[]).await? {
        let zone_nameserver: Result<ZoneNameserver, _> = zone_nameserver.try_into();
        match zone_nameserver {
            Ok(x) => {
                if let Some(zone) = zones.get_mut(&x.id) {
                    zone.0.nameservers.push(x.name);
                }
            }
            Err(e) => {
                error!("failed to parse zone nameserver: {e}");
            }
        }
    }
    for zone_tsig_key in conn.query(r"SELECT * FROM zone_tsig_keys", &[]).await? {
        let zone_tsig_key: Result<ZoneTsigKey, _> = zone_tsig_key.try_into();
        match zone_tsig_key {
            Ok(x) => {
                if let Some(zone) = zones.get_mut(&x.zone_id) {
                    zone.0.tsig_keys.insert(x.name, TsigKey(x.keydata));
                }
            }
            Err(e) => {
                error!("failed to parse zone tsig key: {e}");
            }
        }
    }
    for zone_record in conn
        .query(r"SELECT * FROM zone_records ORDER BY ordering ASC", &[])
        .await?
    {
        let zone_record: Result<ZoneRecord, _> = zone_record.try_into();
        match zone_record {
            Ok(x) => {
                if let Some(zone) = zones.get_mut(&x.zone_id) {
                    zone.0.records.push(Record {
                        name: x.name,
                        type_: x.dns_type,
                        class: Class::IN,
                        ttl: x.ttl,
                        data: x.data,
                    });
                }
            }
            Err(e) => {
                error!("failed to parse zone record: {e}");
            }
        }
    }
    txn.commit().await?;
    let root_zone_id = zones
        .iter()
        .find(|x| x.1 .1.domain.as_ref().is_empty())
        .map(|x| *x.0);
    let mut root_zone = root_zone_id
        .and_then(|x| zones.remove(&x))
        .map(|x| x.0)
        .unwrap_or_else(|| Zone {
            records: vec![],
            zones: Default::default(),
            soa: None,
            nameservers: vec![],
            tsig_keys: Default::default(),
            authoritative: true,
            class: Class::IN,
            allow_md5_tsig: false,
        });
    for (_id, (zone, db_zone)) in zones {
        root_zone.zones.insert(db_zone.domain, zone);
    }
    Ok(root_zone)
}

pub async fn apply_update(conn: &mut Conn, zone_update: &ZoneUpdate) -> Result<(), PostgresError> {
    let txn = conn
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .start()
        .await?;
    let conn = txn.client();

    let zone: Option<DbZone> = conn
        .query_opt(
            r"SELECT * FROM zones WHERE domain = $1",
            &[&zone_update.zone_name.as_ref()],
        )
        .await?
        .map(|x| x.try_into())
        .transpose()?;
    let zone = match zone {
        Some(z) => z,
        None => {
            let zone = DbZone {
                id: Uuid::new_v4(),
                domain: zone_update.zone_name.clone(),
                authoritative: true,
                allow_md5_tsig: false,
            };
            zone.save(conn).await?;
            zone
        }
    };

    'outer: for update in &zone_update.actions {
        match update {
            ZoneUpdateAction::DeleteRecords(name, None) => {
                if name == &zone.domain {
                    conn.execute(r"DELETE FROM records WHERE zone_id = $1 AND name = $2 AND dns_type != 'SOA' AND dns_type != 'NS'", &[&zone.id, &name.as_ref()]).await?;
                } else {
                    conn.execute(
                        r"DELETE FROM records WHERE zone_id = $1 AND name = $2",
                        &[&zone.id, &name.as_ref()],
                    )
                    .await?;
                }
            }
            ZoneUpdateAction::DeleteRecords(name, Some(type_)) => {
                if name == &zone.domain
                    && (*type_ == Type::SOA
                        || *type_ == Type::NS
                        || matches!(type_, Type::Other(_)))
                {
                    continue;
                }
                let type_str: &'static str = type_.into();
                conn.execute(
                    r"DELETE FROM records WHERE zone_id = $1 AND name = $2 AND dns_type = $3",
                    &[&zone.id, &type_str],
                )
                .await?;
            }
            ZoneUpdateAction::DeleteRecord(name, data) => {
                if name == &zone.domain {
                    if matches!(data.dns_type(), Type::SOA | Type::Other(_)) {
                        continue;
                    }
                    if data.dns_type() == Type::NS {
                        let count: i64 = conn.query_one(r"SELECT count(1) FROM records WHERE zone_id = $1 AND dns_type = 'NS'", &[&zone.id]).await?.get(0);
                        if count <= 1 {
                            continue;
                        }
                    }
                }
                let type_str: &'static str = data.dns_type().into();
                conn.execute(r"DELETE FROM records WHERE zone_id = $1 AND name = $2 AND dns_type = $3 AND data = $4 LIMIT 1", &[&zone.id, &type_str, &data.to_string()]).await?;
            }
            ZoneUpdateAction::AddRecord(Record {
                name,
                type_,
                class: _,
                ttl,
                data,
            }) => {
                let mut records = vec![];
                for zone_record in conn.query(r"SELECT * FROM zone_records WHERE zone_id = $1 AND name = $2 ORDER BY ordering ASC", &[&zone.id, &name.as_ref()]).await? {
                    let zone_record: Result<ZoneRecord, _> = zone_record.try_into();
                    match zone_record {
                        Ok(x) => {
                            records.push(x);
                        },
                        Err(e) => {
                            error!("failed to parse zone record: {e}");
                        },
                    }
                }
                if *type_ == Type::CNAME {
                    if records.len() > 1
                        || records
                            .first()
                            .map(|x| x.dns_type != Type::CNAME)
                            .unwrap_or_default()
                    {
                        continue;
                    }
                } else if records.iter().any(|x| x.dns_type == Type::CNAME) {
                    continue;
                }
                if *type_ == Type::SOA {
                    let TypeData::SOA(SoaData { serial: new_serial, .. }) = &data else {
                        continue;
                    };
                    if let Some(ZoneRecord {
                        data: TypeData::SOA(SoaData { serial, .. }),
                        ..
                    }) = records.iter().find(|x| x.dns_type == Type::SOA)
                    {
                        if serial > new_serial {
                            continue;
                        }
                    }
                }
                for mut zone_record in records
                    .into_iter()
                    .filter(|zone_record| zone_record.dns_type == *type_)
                {
                    if *type_ == Type::CNAME || *type_ == Type::SOA || *data == zone_record.data {
                        // update
                        zone_record.ttl = *ttl;
                        zone_record.save(conn).await?;
                        continue 'outer;
                    }
                }
                ZoneRecord {
                    zone_id: zone.id,
                    ordering: 0,
                    name: name.clone(),
                    dns_type: *type_,
                    ttl: *ttl,
                    data: data.clone(),
                }
                .insert_next_order(conn)
                .await?;
            }
        }
    }
    txn.commit().await?;
    Ok(())
}
