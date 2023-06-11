use adns_zone::{Zone, ZoneUpdate};
use tokio::sync::{mpsc, oneshot};

mod static_provider;
pub use static_provider::StaticZoneProvider;

#[cfg(feature = "file_zone")]
mod file;
#[cfg(feature = "file_zone")]
pub use file::FileZoneProvider;
#[cfg(feature = "file_zone")]
mod dynfile;
#[cfg(feature = "file_zone")]
pub use dynfile::DynFileZoneProvider;
mod merge;
pub use merge::{MergeZoneProvider, SendUpdates};

pub struct ZoneProviderUpdate {
    pub update: ZoneUpdate,
    // must be sent AFTER the zone is updated and sent back upstream
    pub response: oneshot::Sender<()>,
}

#[async_trait::async_trait]
pub trait ZoneProvider: Send + Sync + 'static {
    async fn run(
        &mut self,
        sender: mpsc::Sender<Zone>,
        updates: mpsc::Receiver<ZoneProviderUpdate>,
    );
}

#[async_trait::async_trait]
impl ZoneProvider for Box<dyn ZoneProvider> {
    async fn run(
        &mut self,
        sender: mpsc::Sender<Zone>,
        updates: mpsc::Receiver<ZoneProviderUpdate>,
    ) {
        (**self).run(sender, updates).await
    }
}
