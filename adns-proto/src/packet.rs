use thiserror::Error;

use crate::{
    context::{DeserializeContext, SerializeContext},
    Header, Name, Question, Record, TsigData, Type, TypeData,
};

#[derive(Default, Clone, Debug)]
pub struct Packet {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub nameservers: Vec<Record>,
    pub additional_records: Vec<Record>,
}

#[derive(Error, Debug)]
pub enum PacketParseError {
    #[error("the packet header was truncated")]
    HeaderTruncated,
    #[error("the packet was truncated")]
    Truncated,
    #[error("the header was invalid")]
    InvalidHeader,
    #[error("unexpected EOF")]
    UnexpectedEOF,
    #[error("corrupt name, invalid label tag, length, or ptr")]
    CorruptName,
    #[error("invalid UTF8 in name: {0}")]
    UTF8Error(#[from] std::str::Utf8Error),
    #[error("invalid record bytes")]
    CorruptRecord,
}

pub struct ValidatableTsig<'a> {
    pub name: Name,
    pub data: TsigData,
    pub hmac_slice: &'a [u8],
}

impl Packet {
    pub fn parse(bytes: &[u8]) -> Result<(Packet, Option<ValidatableTsig<'_>>), PacketParseError> {
        if bytes.len() < Header::LENGTH {
            return Err(PacketParseError::HeaderTruncated);
        }
        let header = Header::parse(bytes[..Header::LENGTH].try_into().unwrap());
        if !header.validate() {
            return Err(PacketParseError::InvalidHeader);
        }
        if header.is_truncated {
            return Err(PacketParseError::Truncated);
        }
        let mut packet = Packet {
            questions: Vec::with_capacity(header.question_count as usize),
            answers: Vec::with_capacity(header.answer_count as usize),
            nameservers: Vec::with_capacity(header.nameserver_count as usize),
            additional_records: Vec::with_capacity(header.additional_record_count as usize),
            header,
        };
        let mut context = DeserializeContext::new_post_header(bytes);
        for _ in 0..packet.header.question_count {
            packet.questions.push(Question::parse(&mut context)?);
        }
        for _ in 0..packet.header.answer_count {
            packet.answers.push(Record::parse(&mut context)?);
        }
        for _ in 0..packet.header.nameserver_count {
            packet.nameservers.push(Record::parse(&mut context)?);
        }
        let mut tsig = None;
        for i in 0..packet.header.additional_record_count {
            let index = context.index();
            let record = Record::parse(&mut context)?;
            if i == packet.header.additional_record_count - 1 && record.type_ == Type::TSIG {
                let data = match record.data {
                    TypeData::TSIG(data) => data,
                    _ => unreachable!(),
                };
                tsig = Some(ValidatableTsig {
                    name: record.name,
                    data,
                    hmac_slice: &bytes[..index],
                });
                continue;
            }
            packet.additional_records.push(record);
        }

        Ok((packet, tsig))
    }

    pub(crate) fn serialize_open(&self) -> (Header, SerializeContext) {
        let mut context = SerializeContext::default();

        let mut header = self.header.clone();
        header.question_count = self.questions.len().try_into().unwrap();
        header.answer_count = self.answers.len().try_into().unwrap();
        header.nameserver_count = self.nameservers.len().try_into().unwrap();
        header.additional_record_count = self.additional_records.len().try_into().unwrap();
        context.write_blob(header.to_bytes());

        for question in &self.questions {
            question.serialize(&mut context);
        }
        for record in &self.answers {
            record.serialize(&mut context);
        }
        for record in &self.nameservers {
            record.serialize(&mut context);
        }
        for record in &self.additional_records {
            record.serialize(&mut context);
        }

        (header, context)
    }

    pub fn serialize(&self, max_size: usize) -> Vec<u8> {
        let (mut header, context) = self.serialize_open();

        let mut out = context.finalize();
        if out.len() > max_size {
            out.truncate(max_size);
            header.is_truncated = true;
            out[..Header::LENGTH].copy_from_slice(&header.to_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_data::*, Class, Type, TypeData};

    #[test]
    fn test_packet_parse() {
        let packet = Packet::parse(&DNS_QUERY).unwrap().0;
        assert_eq!(packet.questions.len(), 1);

        let question = packet.questions.first().unwrap();
        assert_eq!(question.name, "google.com");
        assert_eq!(question.type_, Type::A);
        assert_eq!(question.class, Class::IN);

        assert_eq!(&DNS_QUERY[..], &packet.serialize(512));

        let packet = Packet::parse(&DNS_RESPONSE).unwrap().0;
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.answers.len(), 1);

        let question = packet.questions.first().unwrap();
        assert_eq!(question.name, "google.com");
        assert_eq!(question.type_, Type::A);
        assert_eq!(question.class, Class::IN);

        let answer = packet.answers.first().unwrap();
        assert_eq!(answer.name, "google.com");
        assert_eq!(answer.type_, Type::A);
        assert_eq!(answer.class, Class::IN);
        assert_eq!(answer.data, TypeData::A("142.250.189.174".parse().unwrap()));

        assert_eq!(&DNS_RESPONSE[..], &packet.serialize(512));
    }
}
