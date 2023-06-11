use std::{path::PathBuf, sync::Arc, time::Duration};

use adns_zone::Zone;
use log::{error, info};
use notify::{
    event::{AccessKind, AccessMode, ModifyKind, RemoveKind},
    EventKind, RecursiveMode, Watcher,
};
use thiserror::Error;
use tokio::{
    select,
    sync::{mpsc, oneshot, Notify},
};

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
        let notify = Arc::new(Notify::new());
        loop {
            match load_config(Arc::new(self.0.clone()), notify.clone()) {
                Ok(()) => break,
                Err(e) => {
                    error!("failed to setup initial zone file watcher: {e} @ {}, retrying in one second", self.0.display());
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
        loop {
            select! {
                _ = notify.notified() => {
                    let zone = loop {
                        match self.read_config().await {
                            Ok(x) => break x,
                            Err(e) => {
                                error!("failed to read zone file update: {e} @ {}, retrying in one second", self.0.display());
                                tokio::time::sleep(Duration::from_secs(1)).await;
                                let notify = notify.notified();
                                futures::pin_mut!(notify);
                                notify.enable();
                            }
                        }
                    };
                    if sender.send(zone).await.is_err() {
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
    #[error("{0}")]
    Notify(#[from] notify::Error),
}

impl FileZoneProvider {
    async fn read_config(&self) -> Result<Zone, FileZoneError> {
        info!("reading zone from {}", self.0.display());
        Ok(serde_yaml::from_str(
            &tokio::fs::read_to_string(&self.0).await?,
        )?)
    }
}

fn load_config(path: Arc<PathBuf>, sender: Arc<Notify>) -> Result<(), FileZoneError> {
    let (watcher_sender, watcher_receiver) = oneshot::channel();
    let mut watcher_receiver = Some(watcher_receiver);

    let path_ref = path.clone();

    let mut watcher =
        notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            assert!(watcher_receiver.is_some());
            match res {
                Ok(event) => {
                    match event.kind {
                        EventKind::Access(AccessKind::Close(AccessMode::Write))
                        | EventKind::Modify(ModifyKind::Name(_))
                        | EventKind::Remove(RemoveKind::File) => (),
                        _ => return,
                    }
                    sender.notify_one();
                    watcher_receiver.take().unwrap().blocking_recv().ok();
                    while let Err(e) = load_config(path.clone(), sender.clone()) {
                        error!("failed to load config watcher: {e}, retrying in 1 second...");
                        std::thread::sleep(Duration::from_secs(1));
                        sender.notify_one();
                    }
                }
                Err(e) => {
                    error!("config watch error: {:?}", e);
                }
            }
        })?;
    watcher.watch(&path_ref, RecursiveMode::NonRecursive)?;
    watcher_sender.send(watcher).ok();

    Ok(())
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
