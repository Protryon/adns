// TODO: CONFIG.database_init_stmts?

use std::{sync::Arc, time::Duration};

use adns_proto::{NameParseError, TypeDataParseError};
use adns_zone::{Zone, ZoneUpdate};
use bb8::{Pool, PooledConnection};
use bb8_postgres::PostgresConnectionManager;
use log::{error, info};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_postgres::{
    config::SslMode, tls::NoTlsStream, Client, Config, Connection, NoTls, Socket,
};

use crate::{
    db::notify::{CockroachNotifier, PostgresNotifier},
    ZoneProvider, ZoneProviderUpdate,
};

use self::notify::NotifierSystem;

mod embedded {
    use refinery::embed_migrations;
    embed_migrations!("migrations");
}

pub type Conn = Client;
pub type ConnOwned = PooledConnection<'static, PostgresConnectionManager<NoTls>>;
pub type DbPool = Pool<PostgresConnectionManager<NoTls>>;

mod notify;
mod zone;

#[derive(Error, Debug)]
pub enum PostgresError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Postgres(#[from] tokio_postgres::Error),
    #[error("{0}")]
    Pool(#[from] bb8::RunError<tokio_postgres::Error>),
    #[error("{0}")]
    Refinery(#[from] refinery::Error),
    #[error("{0}")]
    NameParse(#[from] NameParseError),
    #[error("{0}")]
    Base64(#[from] base64::DecodeError),
    #[error("{0}")]
    TypeDataParse(#[from] TypeDataParseError),
    #[error("{0}")]
    Strum(#[from] strum::ParseError),
}

fn default_port() -> u16 {
    5432
}

fn default_database() -> String {
    "adns".to_string()
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseType {
    #[default]
    Postgres,
    Cockroach,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DbConfig {
    #[serde(default)]
    pub vendor: DatabaseType,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_database")]
    pub database: String,
    pub username: String,
    pub password: String,
}

impl DbConfig {
    pub async fn connect_raw(
        &self,
    ) -> Result<(Client, Connection<Socket, NoTlsStream>), PostgresError> {
        let mut config = Config::new();
        config
            .host(&self.host)
            .port(self.port)
            .user(&self.username)
            .password(&*self.password)
            .dbname(&self.database)
            .connect_timeout(Duration::from_secs(15))
            .ssl_mode(SslMode::Disable);
        Ok(config.connect(NoTls).await?)
    }
}

pub struct DbZoneProvider {
    pool: DbPool,
    notifier: Arc<dyn NotifierSystem>,
}

impl DbZoneProvider {
    pub async fn new(db_config: &DbConfig) -> Result<Self, PostgresError> {
        let mut config = Config::new();
        config
            .host(&db_config.host)
            .port(db_config.port)
            .user(&db_config.username)
            .password(&*db_config.password)
            .dbname(&db_config.database)
            .connect_timeout(Duration::from_secs(15))
            .ssl_mode(SslMode::Disable);
        let _ = db_config.connect_raw().await?;
        let manager = bb8_postgres::PostgresConnectionManager::new(config, NoTls);
        let pool = bb8::Pool::builder()
            .max_size(10)
            .connection_timeout(Duration::from_secs(15))
            .build(manager)
            .await?;

        info!("beginning psql migrations");
        let mut conn = pool.get().await?;
        embedded::migrations::runner().run_async(&mut *conn).await?;
        info!("finished psql migrations");

        let notifier: Arc<dyn NotifierSystem> = match db_config.vendor {
            DatabaseType::Postgres => {
                let db_config = Arc::new(db_config.clone());
                Arc::new(PostgresNotifier::new(pool.clone(), move || {
                    let db_config = db_config.clone();
                    Box::pin(async move { db_config.clone().connect_raw().await })
                }))
            }
            DatabaseType::Cockroach => Arc::new(CockroachNotifier::new(pool.clone()).await?),
        };

        drop(conn);
        Ok(Self { pool, notifier })
    }

    async fn try_load_zone(&self) -> Result<Zone, PostgresError> {
        let mut conn = self.pool.get().await?;
        let zone = zone::load_current_zone(&mut conn).await?;
        Ok(zone)
    }
}

const MAX_UPDATE_RETRY: usize = 3;

async fn try_update(
    pool: &Pool<PostgresConnectionManager<NoTls>>,
    update: &ZoneUpdate,
) -> Result<(), PostgresError> {
    let mut conn = pool.get().await?;
    zone::apply_update(&mut conn, update).await?;
    Ok(())
}

#[async_trait::async_trait]
impl ZoneProvider for DbZoneProvider {
    async fn run(
        &mut self,
        sender: mpsc::Sender<Zone>,
        mut updates: mpsc::Receiver<ZoneProviderUpdate>,
    ) {
        let pool2 = self.pool.clone();
        let notifier2 = self.notifier.clone();
        tokio::spawn(async move {
            while let Some(update) = updates.recv().await {
                let mut attempt = 1usize;
                loop {
                    match try_update(&pool2, &update.update).await {
                        Ok(_) => {
                            update.response.send(()).ok();
                            if let Err(e) = notifier2.notify().await {
                                error!("failed to notify psql of update: {e}");
                            }
                            break;
                        }
                        Err(e) => {
                            if attempt >= MAX_UPDATE_RETRY {
                                error!("failed to apply DNS update: {e}, skipped");
                                break;
                            }
                            error!("failed to apply DNS update: {e}, trying again in 1 second ({attempt}/{MAX_UPDATE_RETRY})");
                            attempt += 1;
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    };
                }
            }
        });
        loop {
            match self.try_load_zone().await {
                Ok(zone) => {
                    if sender.send(zone).await.is_err() {
                        return;
                    }
                    break;
                }
                Err(e) => {
                    error!("failed to load initial zone: {e}, trying again in one second.");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
        loop {
            self.notifier.notified().await;
            match self.try_load_zone().await {
                Ok(zone) => {
                    if sender.send(zone).await.is_err() {
                        return;
                    }
                }
                Err(e) => {
                    error!("failed to load updated zone, skipping: {e}");
                }
            }
        }
    }
}
