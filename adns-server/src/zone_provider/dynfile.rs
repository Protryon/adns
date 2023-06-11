use std::path::PathBuf;

use adns_zone::Zone;
use log::{error, warn};
use tokio::{select, sync::mpsc};

use crate::{FileZoneProvider, ZoneProvider, ZoneProviderUpdate};

pub struct DynFileZoneProvider(pub PathBuf);

#[async_trait::async_trait]
impl ZoneProvider for DynFileZoneProvider {
    async fn run(
        &mut self,
        sender: mpsc::Sender<Zone>,
        mut updates: mpsc::Receiver<ZoneProviderUpdate>,
    ) {
        if !self.0.exists() {
            if let Some(parent) = self.0.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .expect("failed to create initial dyn zone parent dir");
            }
            tokio::fs::write(&self.0, "{}")
                .await
                .expect("failed to create initial dyn zone file");
        }
        let (file_sender, mut file_receiver) = mpsc::channel(10);
        let mut file_provider = FileZoneProvider(self.0.clone());
        let mut file_provider = tokio::spawn(async move {
            file_provider.run(file_sender, mpsc::channel(1).1).await;
        });
        let mut current_zone: Option<Zone> = None;
        loop {
            select! {
                update = updates.recv() => {
                    let Some(update) = update else {
                        warn!("update receiver for dynfile died");
                        break;
                    };
                    let Some(current_zone) = &mut current_zone else {
                        warn!("discarding update received before zone loaded");
                        continue;
                    };
                    update.update.apply_to(current_zone);
                    if let Err(e) = tokio::fs::write(&self.0, serde_yaml::to_string(&*current_zone).unwrap()).await {
                        error!("failed to write zone file for update: {e}");
                        continue;
                    }
                    if sender.send(current_zone.clone()).await.is_err() {
                        break;
                    }
                    update.response.send(()).ok();
                },
                zone = file_receiver.recv() => {
                    let Some(zone) = zone else {
                        error!("zone receiver for dynfile died");
                        break;
                    };
                    current_zone = Some(zone.clone());
                    if sender.send(zone).await.is_err() {
                        break;
                    }
                },
                _ = sender.closed() => {
                    break;
                },
                _ = &mut file_provider => {
                    break;
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::{DynFileZoneProvider, Server};

    #[tokio::test]
    async fn test_file_zone() {
        env_logger::Builder::new()
            .parse_env(env_logger::Env::default().default_filter_or("info"))
            .init();
        Server::new(
            "0.0.0.0:5053".parse().unwrap(),
            "0.0.0.0:5053".parse().unwrap(),
            DynFileZoneProvider(Path::new("./src/zone_provider/test_zone_dyn.yaml").to_path_buf()),
        )
        .run()
        .await;
    }
}
