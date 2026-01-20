use std::{io::ErrorKind, net::SocketAddr, sync::Arc, time::Duration};

use adns_zone::Zone;
use arc_swap::{ArcSwap, Guard};
use log::{debug, error, info};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
    task::JoinHandle,
};

use crate::{metrics, ZoneProvider, ZoneProviderUpdate};

pub struct Server {
    udp_bind: SocketAddr,
    tcp_bind: SocketAddr,
    receiver: mpsc::Receiver<Zone>,
    update_sender: mpsc::Sender<ZoneProviderUpdate>,
    current_zone: Arc<ArcSwap<Zone>>,
}

mod respond;
mod respond_update;

async fn tcp_transaction(
    client: &mut TcpStream,
    updater: &mpsc::Sender<ZoneProviderUpdate>,
    from: &str,
    zone: &Zone,
) -> Result<(), std::io::Error> {
    let len = client.read_u16().await?;
    let mut response = vec![0u8; len as usize];
    client.read_exact(&mut response).await?;
    if let Some(response) = respond::respond(true, zone, updater, from, &response).await {
        let response = response.serialize(zone, u16::MAX as usize);
        for response in response {
            client.write_u16(response.len() as u16).await?;
            client.write_all(&response).await?;
        }
    }
    Ok(())
}

async fn tcp_connection(
    mut client: TcpStream,
    updater: mpsc::Sender<ZoneProviderUpdate>,
    from: &str,
    zone: Guard<Arc<Zone>>,
) -> Result<(), std::io::Error> {
    metrics::TCP_CONNECTIONS.with_label_values(&[from]).inc();
    defer_lite::defer! {
        metrics::TCP_CONNECTIONS.with_label_values(&[from]).dec();
    };
    loop {
        match tokio::time::timeout(
            Duration::from_secs(30),
            tcp_transaction(&mut client, &updater, from, &zone),
        )
        .await
        {
            Ok(Ok(())) => (),
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(std::io::Error::new(
                    ErrorKind::TimedOut,
                    "dns transaction timed out",
                ))
            }
        }
    }
}

pub const UDP_PAYLOAD_SIZE: usize = 1232;

impl Server {
    pub fn new(
        udp_bind: SocketAddr,
        tcp_bind: SocketAddr,
        mut zone_provider: impl ZoneProvider,
    ) -> Self {
        let (sender, receiver) = mpsc::channel(2);
        let (update_sender, update_receiver) = mpsc::channel(2);
        tokio::spawn(async move { zone_provider.run(sender, update_receiver).await });
        Self {
            udp_bind,
            tcp_bind,
            receiver,
            update_sender,
            current_zone: Arc::new(ArcSwap::new(Arc::new(Zone::default()))),
        }
    }

    pub async fn run(mut self) {
        info!("Waiting for initial zone load...");
        match self.receiver.recv().await {
            Some(zone) => {
                self.current_zone.store(Arc::new(zone));
            }
            None => {
                error!("Zone provider died before giving us an initial zone");
                return;
            }
        }
        info!("Initial zone loaded");
        let udp = match UdpSocket::bind(self.udp_bind).await {
            Ok(x) => Arc::new(x),
            Err(e) => {
                error!("failed to bind to UDP port: {e}");
                return;
            }
        };
        info!("Listening on {} (UDP)", self.udp_bind);
        let mut futures: Vec<JoinHandle<()>> = vec![];
        let current_zone = self.current_zone.clone();
        let mut receiver = self.receiver;
        futures.push(tokio::spawn(async move {
            while let Some(zone) = receiver.recv().await {
                info!("updating zone...");
                current_zone.store(Arc::new(zone));
            }
        }));
        let current_zone = self.current_zone.clone();
        let updater = self.update_sender.clone();
        futures.push(tokio::spawn(async move {
            loop {
                let mut recv_buf = vec![0u8; UDP_PAYLOAD_SIZE];
                let (size, from) = match udp.recv_from(&mut recv_buf[..]).await {
                    Ok(x) => x,
                    Err(e) => {
                        error!("udp server failure: {e}");
                        break;
                    }
                };
                recv_buf.truncate(size);
                let zone = current_zone.load();
                let udp = udp.clone();
                let updater = updater.clone();
                tokio::spawn(async move {
                    match respond::respond(
                        false,
                        &zone,
                        &updater,
                        &from.ip().to_string(),
                        &recv_buf,
                    )
                    .await
                    {
                        Some(packet) => {
                            let max_size = UDP_PAYLOAD_SIZE.min(packet.udp_max_size);
                            let serialized = packet.serialize(&zone, max_size);
                            if serialized.len() != 1 {
                                error!("cannot send more than one packet for udp!");
                                return;
                            }
                            if let Err(e) = udp.send_to(&serialized[0], from).await {
                                debug!("UDP send_to error: {e}");
                            }
                        }
                        None => {
                            debug!("packet had no response issued");
                        }
                    }
                });
            }
        }));
        let tcp = match TcpListener::bind(self.tcp_bind).await {
            Ok(x) => x,
            Err(e) => {
                error!("failed to bind to TCP port: {e}");
                return;
            }
        };
        info!("Listening on {} (TCP)", self.tcp_bind);
        let current_zone = self.current_zone.clone();
        let updater = self.update_sender.clone();
        futures.push(tokio::spawn(async move {
            while let Ok((client, from)) = tcp.accept().await {
                let zone = current_zone.load();
                let updater = updater.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        tcp_connection(client, updater, &from.ip().to_string(), zone).await
                    {
                        debug!("TCP connection error: {e}");
                    }
                });
            }
        }));
        let _ = futures::future::select_all(&mut futures).await;
    }
}
