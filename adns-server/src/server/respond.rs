use std::{fmt::Write, time::Instant};

use adns_proto::{
    tsig::{self, TsigError, TsigMode},
    Class, Header, Name, Opcode, Packet, QueryResponse, Question, Record, ResponseCode, Type,
    TypeData, ValidatableTsig,
};
use adns_zone::{AnswerState, Zone, ZoneAnswer};
use log::{info, warn};
use smallvec::{smallvec, SmallVec};
use tokio::sync::{mpsc, oneshot};

use crate::{metrics, ZoneProviderUpdate};

struct QueryContext<'a> {
    zone: &'a Zone,
    question: &'a Question,
    response: &'a mut ZoneAnswer,
    state: &'a mut AnswerState,
}

impl<'a> QueryContext<'a> {
    fn query(&mut self) -> usize {
        let start = self.response.answers.len();
        if self.question.name == "version.bind" && self.question.type_ == Type::TXT {
            self.response.answers.push(Record::new(
                "version.bind".parse().unwrap(),
                3600,
                TypeData::parse_str(Type::TXT, &format!("adns-{}", env!("CARGO_PKG_VERSION")))
                    .unwrap(),
            ));
            *self.state = AnswerState::DomainSeen;
            return self.response.answers.len() - start;
        }
        let substate = self
            .zone
            .answer(None, &Name::default(), self.question, self.response);
        if substate > *self.state {
            *self.state = substate;
        }
        if self.question.type_ == Type::A && self.response.answers.len() == start {
            let mut question = self.question.clone();
            question.type_ = Type::CNAME;
            QueryContext {
                zone: self.zone,
                question: &question,
                response: self.response,
                state: self.state,
            }
            .query();
        }
        self.response.answers.len() - start
    }
}

fn log_query(from: &str, header: &Header, question: &Question, answers: &[Record]) {
    if answers.is_empty() {
        info!(
            "[{}]-{:04X} {} {} -> []",
            from, header.id, question.type_, question.name
        );
    } else if answers.len() == 1 {
        let answer = answers.first().unwrap();
        info!(
            "[{}]-{:04X} {} {} -> {} {} {}",
            from, header.id, question.type_, question.name, answer.name, answer.type_, answer.data
        );
    } else {
        let mut out = String::new();
        for answer in answers {
            write!(
                &mut out,
                "\n-> {} {} {}",
                answer.name, answer.type_, answer.data
            )
            .unwrap();
        }
        info!(
            "[{}]-{:04X} {} {}{}",
            from, header.id, question.type_, question.name, out
        );
    }
}

struct TsigInfo {
    name: Name,
    request_mac: Vec<u8>,
    algorithm: Name,
}

pub struct PacketResponse {
    packet: SmallVec<[Packet; 1]>,
    tsig_info: Option<TsigInfo>,
}

impl PacketResponse {
    pub fn serialize(self, zone: &Zone, max_size: usize) -> SmallVec<[Vec<u8>; 1]> {
        let mut out = SmallVec::with_capacity(self.packet.len());
        let mut previous_mac: Vec<u8> = vec![];
        for (i, packet) in self.packet.into_iter().enumerate() {
            out.push(match &self.tsig_info {
                Some(info) => {
                    let mode = if i == 0 {
                        previous_mac = info.request_mac.clone();
                        TsigMode::Normal
                    } else {
                        TsigMode::TimersOnly
                    };
                    let serialized = tsig::serialize_packet(
                        |name| zone.tsig_keys.get(name).map(|x| x.0.clone()),
                        packet,
                        max_size,
                        info.name.clone(),
                        info.algorithm.clone(),
                        zone.allow_md5_tsig,
                        mode,
                        Some(&previous_mac),
                    );
                    previous_mac = serialized.mac;
                    serialized.packet
                }
                None => packet.serialize(max_size),
            });
        }
        out
    }
}

impl From<Packet> for PacketResponse {
    fn from(packet: Packet) -> Self {
        PacketResponse {
            packet: smallvec![packet],
            tsig_info: None,
        }
    }
}

fn respond_query(from: &str, zone: &Zone, packet: &Packet, mut response: Packet) -> Option<Packet> {
    response.questions = packet.questions.clone();
    let mut state = AnswerState::None;
    let from_str = from.to_string();
    for question in &packet.questions {
        metrics::QUESTIONS
            .with_label_values(&[
                &from_str,
                question.name.raw(),
                question.class.into(),
                question.type_.into(),
            ])
            .inc();
        let mut answer = ZoneAnswer::default();
        QueryContext {
            zone,
            question,
            response: &mut answer,
            state: &mut state,
        }
        .query();
        if answer.is_authoritative {
            response.header.is_authoritative = true;
        }
        log_query(from, &packet.header, question, &answer.answers);
        response.answers.extend(answer.answers);
    }
    for answer in &response.answers {
        let Some(extra_resolve) = (match &answer.data {
            TypeData::CNAME(name) => Some(name),
            TypeData::MX { exchange, .. } => Some(exchange),
            TypeData::SRV { target, .. } => Some(target),
            _ => None,
        }) else {
            continue;
        };
        let question = Question {
            name: extra_resolve.clone(),
            type_: Type::A,
            class: Default::default(),
        };
        let mut answer = ZoneAnswer::default();
        QueryContext {
            zone,
            question: &question,
            response: &mut answer,
            state: &mut state,
        }
        .query();
        if answer.is_authoritative {
            response.header.is_authoritative = true;
        }
        log_query(from, &packet.header, &question, &answer.answers);
        response.additional_records.extend(answer.answers);
    }
    if response.header.is_authoritative
        && response.answers.is_empty()
        && state == AnswerState::DomainSeen
    {
        let mut answer = ZoneAnswer::default();
        for question in &packet.questions {
            let new_question = Question {
                name: question.name.clone(),
                type_: Type::SOA,
                class: Default::default(),
            };
            QueryContext {
                zone,
                question: &new_question,
                response: &mut answer,
                state: &mut state,
            }
            .query();
            if !answer.answers.is_empty() {
                break;
            }
        }
        response.nameservers.extend(answer.answers);
    }
    if state == AnswerState::None {
        response.header.response_code = ResponseCode::NameError;
    }

    Some(response)
}

fn axfr(packet: &Packet) -> Option<&Name> {
    if packet.questions.len() != 1 || !packet.answers.is_empty() || !packet.nameservers.is_empty() {
        return None;
    }
    let question = packet.questions.first().unwrap();
    if question.type_ != Type::AXFR || question.class != Class::IN {
        return None;
    }
    Some(&question.name)
}

fn respond_axfr(
    root_zone: &Zone,
    axfr_name: &Name,
    mut response: Packet,
    from: &str,
) -> SmallVec<[Packet; 1]> {
    let zone = if axfr_name.is_empty() {
        root_zone
    } else if let Some(zone) = root_zone.zones.get(axfr_name) {
        zone
    } else {
        response.header.response_code = ResponseCode::NameError;
        return smallvec![response];
    };
    let soa_question = Question {
        name: axfr_name.clone(),
        type_: Type::SOA,
        class: Default::default(),
    };
    let mut answer = ZoneAnswer::default();
    let mut state = AnswerState::None;
    QueryContext {
        zone: root_zone,
        question: &soa_question,
        response: &mut answer,
        state: &mut state,
    }
    .query();
    let Some(soa) = answer.answers.pop() else {
        warn!("no SOA, cannot do AXFR for {}", axfr_name);
        response.header.response_code = ResponseCode::ServerFailure;
        return smallvec![response];
    };
    let axfr_question = Question {
        name: axfr_name.clone(),
        type_: Type::AXFR,
        class: Default::default(),
    };

    let mut out: SmallVec<[Packet; 1]> = smallvec![];
    {
        let mut response = response.clone();
        response.answers.push(soa.clone());
        log_query(from, &response.header, &axfr_question, &response.answers);
        out.push(response);
    }
    response.questions.clear();
    for records in zone.records.chunks(8) {
        let mut response = response.clone();
        response.answers.extend(records.iter().cloned());
        log_query(from, &response.header, &axfr_question, &response.answers);
        out.push(response);
    }
    {
        let mut response = response.clone();
        response.answers.push(soa);
        log_query(from, &response.header, &axfr_question, &response.answers);
        out.push(response);
    }
    out
}

pub async fn respond(
    is_tcp: bool,
    zone: &Zone,
    updater: &mpsc::Sender<ZoneProviderUpdate>,
    from: &str,
    packet: &[u8],
) -> Option<PacketResponse> {
    let start = Instant::now();
    defer_lite::defer! {
        let elapsed = start.elapsed().as_secs_f64() / 1000000.0;
        metrics::QUERY_US.with_label_values(&[]).observe(elapsed);
    }
    metrics::QUERY.with_label_values(&[from]).inc();
    let (packet, tsig_validatable) = match Packet::parse(packet) {
        Ok(x) => x,
        Err(e) => {
            //TODO: debug
            info!("failed to parse packet: {e}\n{}", hex::encode(packet));
            return None;
        }
    };

    let mut response = Packet {
        header: Header {
            id: packet.header.id,
            query_response: QueryResponse::Response,
            opcode: packet.header.opcode,
            is_authoritative: false,
            is_truncated: false,
            recursion_desired: false,   // TODO
            recursion_available: false, // TODO
            reserved: 0,
            response_code: ResponseCode::NoError,
            ..Default::default()
        },
        ..Default::default()
    };

    if packet.header.query_response != QueryResponse::Query
        || packet.header.response_code != ResponseCode::NoError
    {
        response.header.response_code = ResponseCode::NotImplemented;
        return Some(response.into());
    }
    if packet.header.is_truncated {
        return None;
    }

    let tsig_info: Option<TsigInfo> = if let Some(ValidatableTsig {
        name,
        data: tsig,
        hmac_slice,
    }) = tsig_validatable
    {
        let mut raw_packet = hmac_slice.to_vec();
        let mut new_header = packet.header.clone();
        new_header.additional_record_count -= 1;
        raw_packet[..Header::LENGTH].copy_from_slice(&new_header.to_bytes());

        match tsig::validate(
            |name| zone.tsig_keys.get(name).map(|x| &x.0).cloned(),
            &raw_packet,
            &name,
            &tsig,
            zone.allow_md5_tsig,
            TsigMode::Normal,
            None,
        ) {
            Ok(mac) => Some(TsigInfo {
                request_mac: mac,
                name,
                algorithm: tsig.algorithm,
            }),
            Err(e @ TsigError::TimeMismatch)
            | Err(e @ TsigError::NoAuth)
            | Err(e @ TsigError::MissingKey)
            | Err(e @ TsigError::UnknownAlgorithm) => {
                warn!("TSIG validation error: {e:?}");
                response.additional_records.push(e.to_record(name, tsig));
                response.header.response_code = ResponseCode::NotAuth;
                return Some(response.into());
            }
        }
    } else {
        None
    };

    let response = match packet.header.opcode {
        Opcode::Query => {
            if let Some(axfr_name) = axfr(&packet) {
                if tsig_info.is_none() || !is_tcp {
                    warn!("refused an AXFR");
                    metrics::AXFR
                        .with_label_values(&[from, axfr_name.raw(), "false"])
                        .inc();
                    response.header.response_code = ResponseCode::Refused;
                    return Some(PacketResponse {
                        packet: smallvec![response],
                        tsig_info,
                    });
                }
                metrics::AXFR
                    .with_label_values(&[from, axfr_name.raw(), "true"])
                    .inc();

                return Some(PacketResponse {
                    packet: respond_axfr(zone, axfr_name, response, from),
                    tsig_info,
                });
            }
            respond_query(from, zone, &packet, response)?
        }
        Opcode::Update => {
            if tsig_info.is_none() {
                warn!("refused a RFC2136 update");
                response.header.response_code = ResponseCode::Refused;
                for update in &packet.nameservers {
                    metrics::UPDATES
                        .with_label_values(&[
                            from,
                            update.name.raw(),
                            update.class.into(),
                            update.type_.into(),
                            "false",
                        ])
                        .inc();
                }
                return Some(response.into());
            }

            match super::respond_update::respond_update(from, zone, &packet, response) {
                Ok((update, mut packet)) => {
                    let (sender, receiver) = oneshot::channel();
                    let mut has_failed = false;
                    if updater
                        .send(ZoneProviderUpdate {
                            update,
                            response: sender,
                        })
                        .await
                        .is_err()
                    {
                        has_failed = true;
                    }
                    if !has_failed && receiver.await.is_err() {
                        has_failed = true;
                    }
                    if has_failed {
                        packet.header.response_code = ResponseCode::ServerFailure;
                    }
                    packet
                }
                Err(packet) => packet,
            }
        }
        _ => {
            response.header.response_code = ResponseCode::NotImplemented;
            response
        }
    };

    Some(PacketResponse {
        packet: smallvec![response],
        tsig_info,
    })
}
