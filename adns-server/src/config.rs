use std::{net::SocketAddr, path::PathBuf};

use adns_server::{
    DynFileZoneProvider, FileZoneProvider, MergeZoneProvider, SendUpdates, StaticZoneProvider,
    ZoneProvider,
};
use adns_zone::Zone;
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
    #[cfg(feature = "postgres")]
    Postgres(adns_server::db::DbConfig),
}

#[derive(Error, Debug)]
pub enum ZoneProviderInitError {
    #[cfg(feature = "postgres")]
    #[error("{0}")]
    Postgres(#[from] adns_server::db::PostgresError),
}

impl ZoneProviderConfig {
    #[async_recursion::async_recursion]
    pub async fn construct(self) -> Result<Box<dyn ZoneProvider>, ZoneProviderInitError> {
        let provider: Box<dyn ZoneProvider> = match self {
            ZoneProviderConfig::Static { zone } => Box::new(StaticZoneProvider(zone)),
            ZoneProviderConfig::File { path } => Box::new(FileZoneProvider(path)),
            ZoneProviderConfig::DynFile { path } => Box::new(DynFileZoneProvider(path)),
            ZoneProviderConfig::Merge {
                top,
                bottom,
                send_updates,
            } => Box::new(MergeZoneProvider::new(
                top.construct().await?,
                bottom.construct().await?,
                send_updates,
            )),
            #[cfg(feature = "postgres")]
            ZoneProviderConfig::Postgres(config) => {
                Box::new(adns_server::db::DbZoneProvider::new(&config).await?)
            }
        };
        Ok(provider)
    }
}
