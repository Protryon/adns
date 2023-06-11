use adns_zone::Zone;
use tokio::sync::mpsc;

use crate::{ZoneProvider, ZoneProviderUpdate};

pub struct StaticZoneProvider(pub Zone);

#[async_trait::async_trait]
impl ZoneProvider for StaticZoneProvider {
    async fn run(
        &mut self,
        sender: mpsc::Sender<Zone>,
        updates: mpsc::Receiver<ZoneProviderUpdate>,
    ) {
        drop(updates);
        sender.send(self.0.clone()).await.ok();
        std::mem::forget(sender);
        futures::future::pending::<()>().await;
    }
}
