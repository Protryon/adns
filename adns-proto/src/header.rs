use smallvec::SmallVec;

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum QueryResponse {
    #[default]
    Query,
    Response,
}

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum Opcode {
    #[default]
    Query,
    InverseQuery,
    Status,
    Update,
    Other(u8),
}

impl From<u8> for Opcode {
    fn from(value: u8) -> Self {
        match value {
            0 => Opcode::Query,
            1 => Opcode::InverseQuery,
            2 => Opcode::Status,
            5 => Opcode::Update,
            3..=15 => Opcode::Other(value),
            _ => panic!("invalid range of value for opcode"),
        }
    }
}

impl From<Opcode> for u8 {
    fn from(value: Opcode) -> u8 {
        match value {
            Opcode::Query => 0,
            Opcode::InverseQuery => 1,
            Opcode::Status => 2,
            Opcode::Update => 5,
            Opcode::Other(x) => x,
        }
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum ResponseCode {
    #[default]
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    YxDomain,
    YxRRSet,
    NxRRSet,
    NotAuth,
    NotZone,
    Other(u8),
}

impl From<u8> for ResponseCode {
    fn from(value: u8) -> Self {
        match value {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormatError,
            2 => ResponseCode::ServerFailure,
            3 => ResponseCode::NameError,
            4 => ResponseCode::NotImplemented,
            5 => ResponseCode::Refused,
            6 => ResponseCode::YxDomain,
            7 => ResponseCode::YxRRSet,
            8 => ResponseCode::NxRRSet,
            9 => ResponseCode::NotAuth,
            10 => ResponseCode::NotZone,
            11..=15 => ResponseCode::Other(value),
            _ => panic!("invalid range of value for response code"),
        }
    }
}

impl From<ResponseCode> for u8 {
    fn from(value: ResponseCode) -> u8 {
        match value {
            ResponseCode::NoError => 0,
            ResponseCode::FormatError => 1,
            ResponseCode::ServerFailure => 2,
            ResponseCode::NameError => 3,
            ResponseCode::NotImplemented => 4,
            ResponseCode::Refused => 5,
            ResponseCode::YxDomain => 6,
            ResponseCode::YxRRSet => 7,
            ResponseCode::NxRRSet => 8,
            ResponseCode::NotAuth => 9,
            ResponseCode::NotZone => 10,
            ResponseCode::Other(x) => x,
        }
    }
}

#[derive(Default, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Header {
    pub id: u16,
    pub query_response: QueryResponse,
    pub opcode: Opcode,
    pub is_authoritative: bool,
    pub is_truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub reserved: u8,
    pub response_code: ResponseCode,
    pub question_count: u16,
    pub answer_count: u16,
    pub nameserver_count: u16,
    pub additional_record_count: u16,
}

impl Header {
    pub const LENGTH: usize = 12;

    pub(crate) fn validate(&self) -> bool {
        if matches!(self.opcode, Opcode::Other(_)) {
            return false;
        }
        if matches!(self.response_code, ResponseCode::Other(_)) {
            return false;
        }
        true
    }

    pub(crate) fn parse(data: [u8; Self::LENGTH]) -> Self {
        let flags = u16::from_be_bytes(data[2..4].try_into().unwrap());
        Self {
            id: u16::from_be_bytes(data[..2].try_into().unwrap()),
            query_response: if flags >> 15 & 0b1 == 0 {
                QueryResponse::Query
            } else {
                QueryResponse::Response
            },
            opcode: Opcode::from((flags >> 11) as u8 & 0b1111),
            is_authoritative: flags >> 10 & 0b1 != 0,
            is_truncated: flags >> 9 & 0b1 != 0,
            recursion_desired: flags >> 8 & 0b1 != 0,
            recursion_available: flags >> 7 & 0b1 != 0,
            reserved: (flags >> 4 & 0b111) as u8,
            response_code: ResponseCode::from((flags & 0b1111) as u8),
            question_count: u16::from_be_bytes(data[4..6].try_into().unwrap()),
            answer_count: u16::from_be_bytes(data[6..8].try_into().unwrap()),
            nameserver_count: u16::from_be_bytes(data[8..10].try_into().unwrap()),
            additional_record_count: u16::from_be_bytes(data[10..12].try_into().unwrap()),
        }
    }

    pub fn to_bytes(&self) -> [u8; 12] {
        let mut output: SmallVec<[u8; Self::LENGTH]> = SmallVec::new();
        output.extend(self.id.to_be_bytes());
        let mut flags = 0u16;
        if self.query_response == QueryResponse::Response {
            flags |= 0b1 << 15;
        }
        let opcode: u8 = self.opcode.into();
        let response_code: u8 = self.response_code.into();
        flags |= (opcode as u16 & 0b1111) << 11;
        flags |= (self.is_authoritative as u8 as u16) << 10;
        flags |= (self.is_truncated as u8 as u16) << 9;
        flags |= (self.recursion_desired as u8 as u16) << 8;
        flags |= (self.recursion_available as u8 as u16) << 7;
        flags |= (self.reserved as u16 & 0b111) << 4;
        flags |= response_code as u16 & 0b1111;
        output.extend(flags.to_be_bytes());
        output.extend(self.question_count.to_be_bytes());
        output.extend(self.answer_count.to_be_bytes());
        output.extend(self.nameserver_count.to_be_bytes());
        output.extend(self.additional_record_count.to_be_bytes());
        output.into_inner().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_data::*;

    #[test]
    fn test_header_parse() {
        let header = Header::parse(DNS_QUERY[..Header::LENGTH].try_into().unwrap());
        assert!(header.validate());
        assert!(!header.is_authoritative);
        assert!(!header.is_truncated);
        assert!(header.recursion_desired);
        assert_eq!(header.query_response, QueryResponse::Query);
        assert_eq!(header.question_count, 1);
        assert_eq!(header.additional_record_count, 1);

        assert_eq!(&DNS_QUERY[..Header::LENGTH], &header.to_bytes());

        let header = Header::parse(DNS_RESPONSE[..Header::LENGTH].try_into().unwrap());
        assert!(header.validate());
        assert!(!header.is_authoritative);
        assert!(!header.is_truncated);
        assert!(header.recursion_desired);
        assert!(header.recursion_available);
        assert_eq!(header.response_code, ResponseCode::NoError);
        assert_eq!(header.query_response, QueryResponse::Response);
        assert_eq!(header.question_count, 1);
        assert_eq!(header.answer_count, 1);
        assert_eq!(header.additional_record_count, 1);

        assert_eq!(&DNS_RESPONSE[..Header::LENGTH], &header.to_bytes());
    }
}
