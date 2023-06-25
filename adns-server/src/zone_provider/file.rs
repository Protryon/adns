use std::{path::PathBuf, time::Duration};

use adns_zone::Zone;
use log::{error, info};
use really_notify::FileWatcherConfig;
use thiserror::Error;
use tokio::{select, sync::mpsc};

use crate::{ZoneProvider, ZoneProviderUpdate};

pub struct FileZoneProvider(pub PathBuf);

#[async_trait::async_trait]
impl ZoneProvider for FileZoneProvider {
    async fn run(
        &mut self,
        sender: mpsc::Sender<Zone>,
        updates: mpsc::Receiver<ZoneProviderUpdate>,
    ) {
        drop(updates);
        let zone = loop {
            match self.read_config().await {
                Ok(x) => break x,
                Err(e) => {
                    error!(
                        "failed to read initial zone file: {e} @ {}, retrying in one second",
                        self.0.display()
                    );
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        };
        if sender.send(zone).await.is_err() {
            return;
        }
        let mut receiver = FileWatcherConfig::new(&self.0, "zone")
            .with_parser(move |x| serde_yaml::from_slice(&x))
            .start();
        loop {
            select! {
                update = receiver.recv() => {
                    let Some(update) = update else {
                        return;
                    };
                    if sender.send(update).await.is_err() {
                        return;
                    }
                },
                _ = sender.closed() => {
                    return;
                }
            }
        }
    }
}

#[derive(Error, Debug)]
pub enum FileZoneError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Yaml(#[from] serde_yaml::Error),
}

impl FileZoneProvider {
    async fn read_config(&self) -> Result<Zone, FileZoneError> {
        info!("reading zone from {}", self.0.display());
        Ok(serde_yaml::from_str(
            &tokio::fs::read_to_string(&self.0).await?,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::{FileZoneProvider, Server};

    #[tokio::test]
    async fn test_file_zone() {
        env_logger::Builder::new()
            .parse_env(env_logger::Env::default().default_filter_or("info"))
            .init();
        Server::new(
            "0.0.0.0:5053".parse().unwrap(),
            "0.0.0.0:5053".parse().unwrap(),
            FileZoneProvider(Path::new("./src/zone_provider/test_zone.yaml").to_path_buf()),
        )
        .run()
        .await;
    }
}
