use adns_zone::Zone;
use serde::{Deserialize, Serialize};
use tokio::{select, sync::mpsc};

use crate::{ZoneProvider, ZoneProviderUpdate};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default)]
#[serde(rename_all = "snake_case")]
pub enum SendUpdates {
    #[default]
    ToTop,
    ToBottom,
}

pub struct MergeZoneProvider<TOP: ZoneProvider, BOTTOM: ZoneProvider> {
    top: Option<TOP>,
    bottom: Option<BOTTOM>,
    send_updates: SendUpdates,
}

impl<TOP: ZoneProvider, BOTTOM: ZoneProvider> MergeZoneProvider<TOP, BOTTOM> {
    pub fn new(top: TOP, bottom: BOTTOM, send_updates: SendUpdates) -> Self {
        Self {
            top: Some(top),
            bottom: Some(bottom),
            send_updates,
        }
    }
}

#[async_trait::async_trait]
impl<TOP: ZoneProvider, BOTTOM: ZoneProvider> ZoneProvider for MergeZoneProvider<TOP, BOTTOM> {
    async fn run(
        &mut self,
        sender: mpsc::Sender<Zone>,
        mut updates: mpsc::Receiver<ZoneProviderUpdate>,
    ) {
        let (top_sender, mut top_receiver) = mpsc::channel(2);
        let (top_update_sender, top_update_receiver) = mpsc::channel(2);
        let (bottom_sender, mut bottom_receiver) = mpsc::channel(2);
        let (bottom_update_sender, bottom_update_receiver) = mpsc::channel(2);
        let mut top = self.top.take().unwrap();
        let mut bottom = self.bottom.take().unwrap();
        let mut top_task = tokio::spawn(async move {
            top.run(top_sender, top_update_receiver).await;
        });
        let mut bottom_task = tokio::spawn(async move {
            bottom.run(bottom_sender, bottom_update_receiver).await;
        });
        let mut current_top_zone = None::<Zone>;
        let mut current_bottom_zone = None::<Zone>;
        loop {
            select! {
                top_zone = top_receiver.recv() => {
                    let Some(top_zone) = top_zone else {
                        break;
                    };
                    current_top_zone = Some(top_zone);
                    if let (Some(top), Some(bottom)) = (&current_top_zone, &current_bottom_zone) {
                        let mut zone = bottom.clone();
                        zone.merge_from(top.clone());
                        if sender.send(zone).await.is_err() {
                            break;
                        }
                    }
                },
                bottom_zone = bottom_receiver.recv() => {
                    let Some(bottom_zone) = bottom_zone else {
                        break;
                    };
                    current_bottom_zone = Some(bottom_zone);
                    if let (Some(top), Some(bottom)) = (&current_top_zone, &current_bottom_zone) {
                        let mut zone = bottom.clone();
                        zone.merge_from(top.clone());
                        if sender.send(zone).await.is_err() {
                            break;
                        }
                    }
                },
                update = updates.recv() => {
                    let Some(update) = update else {
                        break;
                    };
                    match self.send_updates {
                        SendUpdates::ToTop => {
                            top_update_sender.send(update).await.ok();
                        },
                        SendUpdates::ToBottom => {
                            bottom_update_sender.send(update).await.ok();
                        },
                    }
                },
                _ = &mut top_task => {
                    break;
                },
                _ = &mut bottom_task => {
                    break;
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::{
        zone_provider::merge::SendUpdates, DynFileZoneProvider, FileZoneProvider,
        MergeZoneProvider, Server,
    };

    #[tokio::test]
    async fn test_file_zone() {
        env_logger::Builder::new()
            .parse_env(env_logger::Env::default().default_filter_or("info"))
            .init();
        Server::new(
            "0.0.0.0:5053".parse().unwrap(),
            "0.0.0.0:5053".parse().unwrap(),
            MergeZoneProvider::new(
                DynFileZoneProvider(
                    Path::new("./src/zone_provider/test_zone_dyn.yaml").to_path_buf(),
                ),
                FileZoneProvider(Path::new("./src/zone_provider/test_zone.yaml").to_path_buf()),
                SendUpdates::ToTop,
            ),
        )
        .run()
        .await;
    }
}
