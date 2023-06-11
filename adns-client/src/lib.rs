use std::net::SocketAddr;

use adns_proto::{Header, Packet, PacketParseError, Question};
use rand::{thread_rng, Rng};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, ToSocketAddrs, UdpSocket},
};

pub struct DnsClient {
    udp: UdpSocket,
}

#[derive(Error, Debug)]
pub enum DnsQueryError {
    #[error("packet ID mismatch")]
    IDMismatch,
    #[error("packet too large >64KB")]
    PacketTooLarge,
    #[error("{0}")]
    IoError(#[from] std::io::Error),
    #[error("dns parse error {0}")]
    PacketParseError(#[from] PacketParseError),
}

impl DnsClient {
    pub async fn new() -> Result<Self, DnsQueryError> {
        Ok(Self {
            udp: UdpSocket::bind("0.0.0.0:0".parse::<SocketAddr>().unwrap()).await?,
        })
    }

    pub async fn query(
        &mut self,
        servers: impl ToSocketAddrs,
        questions: Vec<Question>,
    ) -> Result<Packet, DnsQueryError> {
        let id: u16 = thread_rng().gen();
        let packet = Packet {
            header: Header {
                id,
                recursion_desired: true,
                recursion_available: true,
                ..Default::default()
            },
            questions,
            ..Default::default()
        };
        let serialized = packet.serialize(usize::MAX);
        if serialized.len() > 512 {
            self.query_tcp(&servers, id, &serialized).await
        } else {
            self.udp.send_to(&serialized, &servers).await?;
            let mut response = [0u8; 512];
            let mut size;
            loop {
                size = self.udp.recv(&mut response).await?;
                if size < 2 || u16::from_be_bytes(response[..2].try_into().unwrap()) != id {
                    continue;
                }
                break;
            }
            match Packet::parse(&response[..size]) {
                Ok(packet) => Ok(packet.0),
                Err(PacketParseError::Truncated) => self.query_tcp(&servers, id, &serialized).await,
                Err(e) => Err(e.into()),
            }
        }
    }

    async fn query_tcp(
        &mut self,
        servers: impl ToSocketAddrs,
        id: u16,
        packet: &[u8],
    ) -> Result<Packet, DnsQueryError> {
        let mut client = TcpStream::connect(servers).await?;
        client
            .write_u16(
                packet
                    .len()
                    .try_into()
                    .map_err(|_| DnsQueryError::PacketTooLarge)?,
            )
            .await?;
        client.write_all(packet).await?;
        let len = client.read_u16().await?;
        let mut response = vec![0u8; len as usize];
        client.read_exact(&mut response).await?;

        let packet = Packet::parse(&response)?.0;
        if packet.header.id != id {
            return Err(DnsQueryError::IDMismatch);
        }
        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use adns_proto::Type;

    use super::*;

    #[tokio::test]
    async fn test_query() {
        let mut client = DnsClient::new().await.unwrap();
        let response = client
            .query(
                "8.8.8.8:53",
                vec![Question::new(Type::A, "google.com").unwrap()],
            )
            .await
            .unwrap();
        for answer in &response.answers {
            println!("{answer}");
        }
    }
}
