use std::{borrow::Cow, fmt, net::AddrParseError, num::ParseIntError};

use hex::FromHexError;
use thiserror::Error;

use crate::{NameParseError, SoaData, TsigData, Type, TypeData};

#[derive(Error, Debug)]
pub enum TypeDataParseError {
    #[error("argument string is malformed")]
    MalformedString,
    #[error("no arguments specified")]
    NoArguments,
    #[error("missing expected argument")]
    MissingArgument,

    #[error("invalid UTF8 in name: {0}")]
    UTF8Error(#[from] std::str::Utf8Error),
    #[error("failed to parse domain name: {0}")]
    NameParseError(#[from] NameParseError),
    #[error("failed to parse address: {0}")]
    AddrParseError(#[from] AddrParseError),
    #[error("failed to parse integer: {0}")]
    ParseIntError(#[from] ParseIntError),
    #[error("failed to parse hex: {0}")]
    FromHexError(#[from] FromHexError),
}

fn fmt_arg(input: &str) -> Cow<'_, str> {
    if needs_escape(input) {
        Cow::Owned(do_escape(input))
    } else {
        Cow::Borrowed(input)
    }
}

fn needs_escape(input: &str) -> bool {
    input
        .chars()
        .any(|x| x == '"' || x.is_ascii_whitespace() || x == '\\')
}

fn do_escape(input: &str) -> String {
    let mut out = "\"".to_string();
    for c in input.chars() {
        if c == '"' || c == '\\' || c.is_ascii_whitespace() {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

fn parse_args(input: &str) -> Result<Vec<String>, TypeDataParseError> {
    let mut out = vec![];
    let mut escaped = false;
    let mut quoted = false;
    let mut current = String::new();
    for c in input.trim().chars() {
        if escaped {
            current.push(c);
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        } else if c == '"' && !quoted {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            quoted = true;
        } else if c == '"' && quoted {
            out.push(std::mem::take(&mut current));
            quoted = false;
        } else if c.is_ascii_whitespace() {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
        } else {
            current.push(c);
        }
    }
    if quoted || escaped {
        return Err(TypeDataParseError::MalformedString);
    }
    if !current.is_empty() {
        out.push(std::mem::take(&mut current));
    }
    Ok(out)
}

impl fmt::Display for TypeData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypeData::A(x) => write!(f, "{x}")?,
            TypeData::DNAME(x) | TypeData::NS(x) | TypeData::CNAME(x) | TypeData::PTR(x) => {
                write!(f, "{x}")?
            }
            TypeData::SOA(SoaData {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            }) => {
                write!(
                    f,
                    "{} {} {} {} {} {} {}",
                    mname, rname, serial, refresh, retry, expire, minimum
                )?;
            }
            TypeData::HINFO { cpu, os } => {
                write!(f, "{} {}", fmt_arg(cpu), fmt_arg(os))?;
            }
            TypeData::MX {
                preference,
                exchange,
            } => {
                write!(f, "{} {}", preference, exchange)?;
            }
            TypeData::TXT(texts) => {
                if texts.is_empty() {
                    return Ok(());
                }
                write!(f, "{}", fmt_arg(texts.first().unwrap()))?;
                for text in texts[1..].iter() {
                    write!(f, " {}", fmt_arg(text))?;
                }
            }
            TypeData::AAAA(x) => write!(f, "{x}")?,
            TypeData::LOC {
                version,
                size,
                horiz_pre,
                vert_pre,
                latitude,
                longitude,
                altitude,
            } => {
                write!(
                    f,
                    "{} {} {} {} {} {} {}",
                    version, size, horiz_pre, vert_pre, latitude, longitude, altitude
                )?;
            }
            TypeData::SRV {
                priority,
                weight,
                port,
                target,
            } => {
                write!(f, "{} {} {} {}", priority, weight, port, target)?;
            }
            TypeData::CERT {
                type_,
                key_tag,
                algorithm,
                data,
            } => {
                write!(
                    f,
                    "{} {} {} {}",
                    type_,
                    key_tag,
                    algorithm,
                    hex::encode(data)
                )?;
            }
            TypeData::SSHFP {
                algorithm,
                fp_type,
                fingerprint,
            } => {
                write!(f, "{} {} {}", algorithm, fp_type, hex::encode(fingerprint))?;
            }
            TypeData::TSIG(TsigData {
                algorithm,
                time_signed,
                fudge,
                mac,
                original_id,
                error,
                other_data,
            }) => write!(
                f,
                "{algorithm} {time_signed} {fudge} {} {original_id} {error:?} {}",
                hex::encode(mac),
                hex::encode(other_data)
            )?,
            TypeData::URI {
                priority,
                weight,
                target,
            } => {
                write!(f, "{} {} {}", priority, weight, target)?;
            }
            TypeData::Other(_, x) => write!(f, "{}", hex::encode(x))?,
            TypeData::OPT(opt_data) => {
                for x in &opt_data.items {
                    write!(f, "{} {} bytes / ", x.code, x.data.len())?;
                }
            }
        }
        Ok(())
    }
}

impl TypeData {
    pub fn parse_str(type_: Type, input: &str) -> Result<TypeData, TypeDataParseError> {
        let args = parse_args(input)?;
        let Some(first) = args.first() else {
            return Err(TypeDataParseError::NoArguments);
        };

        Ok(match type_ {
            Type::A => TypeData::A(first.parse()?),
            Type::NS => TypeData::NS(first.parse()?),
            Type::CNAME => TypeData::CNAME(first.parse()?),
            Type::SOA => TypeData::SOA(SoaData {
                mname: first.parse()?,
                rname: args
                    .get(1)
                    .ok_or(TypeDataParseError::MissingArgument)?
                    .parse()?,
                serial: args
                    .get(2)
                    .ok_or(TypeDataParseError::MissingArgument)?
                    .parse()?,
                refresh: args
                    .get(3)
                    .ok_or(TypeDataParseError::MissingArgument)?
                    .parse()?,
                retry: args
                    .get(4)
                    .ok_or(TypeDataParseError::MissingArgument)?
                    .parse()?,
                expire: args
                    .get(5)
                    .ok_or(TypeDataParseError::MissingArgument)?
                    .parse()?,
                minimum: args
                    .get(6)
                    .ok_or(TypeDataParseError::MissingArgument)?
                    .parse()?,
            }),
            Type::PTR => TypeData::PTR(first.parse()?),
            Type::HINFO => TypeData::HINFO {
                cpu: first.clone(),
                os: args
                    .get(1)
                    .ok_or(TypeDataParseError::MissingArgument)?
                    .clone(),
            },
            Type::MX => TypeData::MX {
                preference: first.parse()?,
                exchange: args
                    .get(1)
                    .ok_or(TypeDataParseError::MissingArgument)?
                    .parse()?,
            },
            Type::TXT => TypeData::TXT(smallvec::smallvec![args.join(" ")]),
            Type::AAAA => TypeData::AAAA(first.parse()?),
            Type::LOC => TypeData::LOC {
                version: first.parse()?,
                size: args
                    .get(1)
                    .ok_or(TypeDataParseError::MissingArgument)?
                    .parse()?,
                horiz_pre: args
                    .get(2)
                    .ok_or(TypeDataParseError::MissingArgument)?
                    .parse()?,
                vert_pre: args
                    .get(3)
                    .ok_or(TypeDataParseError::MissingArgument)?
                    .parse()?,
                latitude: args
                    .get(4)
                    .ok_or(TypeDataParseError::MissingArgument)?
                    .parse()?,
                longitude: args
                    .get(5)
                    .ok_or(TypeDataParseError::MissingArgument)?
                    .parse()?,
                altitude: args
                    .get(6)
                    .ok_or(TypeDataParseError::MissingArgument)?
                    .parse()?,
            },
            Type::SRV => TypeData::SRV {
                priority: first.parse()?,
                weight: args
                    .get(1)
                    .ok_or(TypeDataParseError::MissingArgument)?
                    .parse()?,
                port: args
                    .get(2)
                    .ok_or(TypeDataParseError::MissingArgument)?
                    .parse()?,
                target: args
                    .get(3)
                    .ok_or(TypeDataParseError::MissingArgument)?
                    .parse()?,
            },
            Type::CERT => TypeData::CERT {
                type_: first.parse()?,
                key_tag: args
                    .get(1)
                    .ok_or(TypeDataParseError::MissingArgument)?
                    .parse()?,
                algorithm: args
                    .get(2)
                    .ok_or(TypeDataParseError::MissingArgument)?
                    .parse()?,
                data: hex::decode(args.get(3).ok_or(TypeDataParseError::MissingArgument)?)?,
            },
            Type::DNAME => TypeData::DNAME(first.parse()?),
            Type::SSHFP => TypeData::SSHFP {
                algorithm: first.parse()?,
                fp_type: args
                    .get(1)
                    .ok_or(TypeDataParseError::MissingArgument)?
                    .parse()?,
                fingerprint: hex::decode(args.get(2).ok_or(TypeDataParseError::MissingArgument)?)?,
            },
            // TSIG cannot be parsed
            Type::URI => TypeData::URI {
                priority: first.parse()?,
                weight: args
                    .get(1)
                    .ok_or(TypeDataParseError::MissingArgument)?
                    .parse()?,
                target: args
                    .get(1)
                    .ok_or(TypeDataParseError::MissingArgument)?
                    .clone(),
            },
            type_ => TypeData::Other(type_, hex::decode(first)?.into()),
        })
    }
}
