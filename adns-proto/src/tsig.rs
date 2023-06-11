use crate::{
    context::SerializeContext, Class, Header, Name, Packet, Record, TsigData, TsigResponseCode,
    Type, TypeData,
};
use chrono::{TimeZone, Utc};
use constant_time_eq::constant_time_eq;
use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TsigError {
    #[error("unknown algorithm")]
    UnknownAlgorithm,
    #[error("missing key")]
    MissingKey,
    #[error("signature mismatch")]
    NoAuth,
    #[error("time mismatch")]
    TimeMismatch,
}

pub fn extract_tsig(packet: &Packet) -> Option<(Packet, Name, TsigData)> {
    let last = packet.additional_records.last()?;
    if last.type_ != Type::TSIG {
        return None;
    }
    let mut packet = packet.clone();
    let tsig = packet.additional_records.pop()?;
    let TypeData::TSIG(data) = tsig.data else {
        return None;
    };
    Some((packet, tsig.name, data))
}

pub fn calculate(
    key_lookup: impl FnOnce(&str) -> Option<Vec<u8>>,
    data: &[u8],
    name: &Name,
    tsig: &TsigData,
    allow_md5: bool,
    mode: TsigMode,
    request_mac: Option<&[u8]>,
) -> Result<Vec<u8>, TsigError> {
    if data.len() < 2 {
        return Err(TsigError::MissingKey);
    }
    let Some(key) = key_lookup(name.as_ref()) else {
        return Err(TsigError::MissingKey);
    };

    let now = Utc::now();
    let time_signed = Utc
        .timestamp_opt(tsig.time_signed as i64, 0)
        .single()
        .ok_or(TsigError::TimeMismatch)?;
    let fudge = chrono::Duration::seconds(tsig.fudge as i64);
    if now - fudge > time_signed || now + fudge < time_signed {
        return Err(TsigError::TimeMismatch);
    }

    let mut buf = Vec::with_capacity(data.len() + request_mac.map(|x| x.len()).unwrap_or_default());

    if let Some(request_mac) = request_mac {
        let len = request_mac.len() as u16;
        buf.extend(len.to_be_bytes());
        buf.extend(request_mac);
    }
    buf.extend(tsig.original_id.to_be_bytes());
    buf.extend(&data[2..]);
    let mut context = SerializeContext::default();
    match mode {
        TsigMode::TimersOnly => {
            context.write_blob(&tsig.time_signed.to_be_bytes()[2..8]);
            context.write_blob(tsig.fudge.to_be_bytes());
        }
        TsigMode::Normal => {
            context.write_name(name);
            context.wipe_compression();
            context.write_blob(255u16.to_be_bytes());
            context.write_blob(0u32.to_be_bytes());
            context.write_name(&tsig.algorithm);
            context.write_blob(&tsig.time_signed.to_be_bytes()[2..8]);
            context.write_blob(tsig.fudge.to_be_bytes());
            context.write_blob(<TsigResponseCode as Into<u16>>::into(tsig.error).to_be_bytes());
            context.write_blob((tsig.other_data.len() as u16).to_be_bytes());
            context.write_blob(&tsig.other_data);
        }
    }
    let out = context.finalize();
    buf.extend(out);

    let calculated_mac = match tsig.algorithm.as_ref() {
        "hmac-sha1" => {
            let mut mac = Hmac::<Sha1>::new_from_slice(&key).unwrap();
            mac.update(&buf);
            mac.finalize().into_bytes().to_vec()
        }
        "hmac-sha224" => {
            let mut mac = Hmac::<Sha224>::new_from_slice(&key).unwrap();
            mac.update(&buf);
            mac.finalize().into_bytes().to_vec()
        }
        "hmac-sha256" => {
            let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
            mac.update(&buf);
            mac.finalize().into_bytes().to_vec()
        }
        "hmac-sha384" => {
            let mut mac = Hmac::<Sha384>::new_from_slice(&key).unwrap();
            mac.update(&buf);
            mac.finalize().into_bytes().to_vec()
        }
        "hmac-sha512" => {
            let mut mac = Hmac::<Sha512>::new_from_slice(&key).unwrap();
            mac.update(&buf);
            mac.finalize().into_bytes().to_vec()
        }
        "hmac-md5.sig-alg.reg.int" if allow_md5 => {
            let mut mac = Hmac::<Md5>::new_from_slice(&key).unwrap();
            mac.update(&buf);
            mac.finalize().into_bytes().to_vec()
        }
        _ => return Err(TsigError::UnknownAlgorithm),
    };

    Ok(calculated_mac)
}

#[derive(Clone, Copy, Debug)]
pub enum TsigMode {
    TimersOnly,
    Normal,
}

#[derive(Clone, Debug)]
pub struct SerializedPacket {
    pub packet: Vec<u8>,
    pub mac: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
pub fn serialize_packet(
    key_lookup: impl FnOnce(&str) -> Option<Vec<u8>>,
    packet: Packet,
    max_size: usize,
    name: Name,
    algorithm: Name,
    allow_md5: bool,
    mode: TsigMode,
    request_mac: Option<&[u8]>,
) -> SerializedPacket {
    let (mut header, mut context) = packet.serialize_open();
    let mut data = TsigData {
        algorithm,
        time_signed: Utc::now().timestamp() as u64,
        fudge: 300,
        mac: vec![],
        original_id: header.id,
        error: TsigResponseCode::NoError,
        other_data: vec![],
    };
    let (record, mac) = match calculate(
        key_lookup,
        context.current(),
        &name,
        &data,
        allow_md5,
        mode,
        request_mac,
    ) {
        Ok(mac) => {
            data.mac = mac.clone();
            let mut record = Record::new(name, 0, TypeData::TSIG(data));
            record.class = Class::Other(255);
            (record, mac)
        }
        Err(e) => (e.to_record(name, data), vec![]),
    };
    header.additional_record_count += 1;
    context.wipe_compression();
    record.serialize(&mut context);

    let mut out = context.finalize();
    if out.len() > max_size {
        out.truncate(max_size);
        header.is_truncated = true;
    }
    out[..Header::LENGTH].copy_from_slice(&header.to_bytes());
    SerializedPacket { packet: out, mac }
}

impl TsigError {
    pub fn to_record(&self, name: Name, tsig: TsigData) -> Record {
        let mut record = Record::new(
            name,
            0,
            TypeData::TSIG(TsigData {
                algorithm: tsig.algorithm,
                time_signed: tsig.time_signed,
                fudge: tsig.fudge,
                mac: vec![],
                original_id: tsig.original_id,
                error: match *self {
                    TsigError::UnknownAlgorithm => TsigResponseCode::BadKey,
                    TsigError::MissingKey => TsigResponseCode::BadKey,
                    TsigError::NoAuth => TsigResponseCode::BadSig,
                    TsigError::TimeMismatch => TsigResponseCode::BadTime,
                },
                other_data: vec![],
            }),
        );
        record.class = Class::Other(255);
        record
    }
}

pub fn validate(
    key_lookup: impl FnOnce(&str) -> Option<Vec<u8>>,
    packet: &[u8],
    name: &Name,
    tsig: &TsigData,
    allow_md5: bool,
    mode: TsigMode,
    request_mac: Option<&[u8]>,
) -> Result<Vec<u8>, TsigError> {
    //TODO: ideally we take the original network serialization
    let mac = calculate(key_lookup, packet, name, tsig, allow_md5, mode, request_mac)?;

    if !constant_time_eq(&tsig.mac, &mac) {
        Err(TsigError::NoAuth)
    } else {
        Ok(mac)
    }
}

// pub fn generate(key_lookup: impl FnOnce(&str) -> Option<Vec<u8>>, mut packet: Packet, request_mac: Option<&[u8]>) -> Result<Packet, TsigError> {
//     let mut tsig = packet.additional_records.pop().ok_or(TsigError::MissingTsig)?;
//     if tsig.type_ != Type::TSIG {
//         return Err(TsigError::MissingTsig);
//     }
//     packet.header.additional_record_count -= 1;
//     let TypeData::TSIG { algorithm, time_signed, fudge, mac, original_id, error, other_data } = &mut tsig.data else {
//         return Err(TsigError::MissingTsig);
//     };
//     // if *time_signed == 0 {
//     //     *time_signed = Utc::now().timestamp() as u32;
//     // }
//     // if *fudge == 0 {
//     //     *fudge = 300;
//     // }
//     let new_id = packet.header.id;
//     packet.header.id = *original_id;
//     let Some(key) = key_lookup(tsig.name.as_ref()) else {
//         return Err(TsigError::MissingKey);
//     };

//     let mut buf = packet.serialize(usize::MAX);

//     if let Some(request_mac) = request_mac {
//         let len = request_mac.len() as u16;
//         let mut out = vec![];
//         out.extend(len.to_be_bytes());
//         out.extend(request_mac);
//         buf.extend(out);
//     }
//     let mut context = SerializeContext::default();
//     context.write_name(&tsig.name);
//     context.wipe_compression();
//     context.write_blob(255u16.to_be_bytes());
//     context.write_blob(0u32.to_be_bytes());
//     context.write_name(&algorithm);
//     context.write_blob(&time_signed.to_be_bytes()[1..4]);
//     context.write_blob(fudge.to_be_bytes());
//     context.write_blob(error.to_be_bytes());
//     context.write_blob((other_data.len() as u16).to_be_bytes());
//     context.write_blob(&other_data);
//     let out = context.finalize();
//     buf.extend(out);

//     let calculated_mac = match algorithm.as_ref() {
//         "hmac-sha1" => {
//             let mut mac = Hmac::<Sha1>::new_from_slice(&key)?;
//             mac.update(&buf);
//             mac.finalize().into_bytes().to_vec()
//         },
//         "hmac-sha224" => {
//             let mut mac = Hmac::<Sha224>::new_from_slice(&key)?;
//             mac.update(&buf);
//             mac.finalize().into_bytes().to_vec()
//         },
//         "hmac-sha256" => {
//             let mut mac = Hmac::<Sha256>::new_from_slice(&key)?;
//             mac.update(&buf);
//             mac.finalize().into_bytes().to_vec()
//         },
//         "hmac-sha384" => {
//             let mut mac = Hmac::<Sha384>::new_from_slice(&key)?;
//             mac.update(&buf);
//             mac.finalize().into_bytes().to_vec()
//         },
//         "hmac-sha512" => {
//             let mut mac = Hmac::<Sha512>::new_from_slice(&key)?;
//             mac.update(&buf);
//             mac.finalize().into_bytes().to_vec()
//         },
//         _ => return Err(TsigError::UnknownAlgorithm),
//     };
//     *mac = calculated_mac;

//     packet.header.id = new_id;
//     packet.additional_records.push(tsig);
//     packet.header.additional_record_count += 1;
//     Ok(packet)
// }
