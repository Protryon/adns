use std::{net::SocketAddr, path::PathBuf};

use adns_server::{
    DynFileZoneProvider, FileZoneProvider, MergeZoneProvider, SendUpdates, StaticZoneProvider,
    ZoneProvider,
};
use adns_zone::Zone;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub prometheus_bind: Option<SocketAddr>,
    pub servers: Vec<DnsServerConfig>,
}

#[derive(Serialize, Deserialize)]
pub struct DnsServerConfig {
    pub udp_bind: SocketAddr,
    pub tcp_bind: SocketAddr,
    pub zone: ZoneProviderConfig,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum ZoneProviderConfig {
    Static {
        zone: Zone,
    },
    File {
        path: PathBuf,
    },
    DynFile {
        path: PathBuf,
    },
    Merge {
        top: Box<ZoneProviderConfig>,
        bottom: Box<ZoneProviderConfig>,
        #[serde(default)]
        send_updates: SendUpdates,
    },
}

impl ZoneProviderConfig {
    pub fn construct(self) -> Box<dyn ZoneProvider> {
        match self {
            ZoneProviderConfig::Static { zone } => Box::new(StaticZoneProvider(zone)),
            ZoneProviderConfig::File { path } => Box::new(FileZoneProvider(path)),
            ZoneProviderConfig::DynFile { path } => Box::new(DynFileZoneProvider(path)),
            ZoneProviderConfig::Merge {
                top,
                bottom,
                send_updates,
            } => Box::new(MergeZoneProvider::new(
                top.construct(),
                bottom.construct(),
                send_updates,
            )),
        }
    }
}
