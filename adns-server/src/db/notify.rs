use std::{pin::Pin, sync::Arc, time::Duration};

use futures::{pin_mut, Future, FutureExt, StreamExt};
use log::{error, info, warn};
use tokio::{select, sync::Notify};
use tokio_postgres::{tls::NoTlsStream, types::ToSql, AsyncMessage, Connection, Socket};

use super::{Conn, DbPool, PostgresError};

#[async_trait::async_trait]
pub trait NotifierSystem: Send + Sync {
    async fn notify(&self) -> Result<(), PostgresError>;

    async fn notified(&self);
}

pub struct PostgresNotifier {
    pool: DbPool,
    notify: Arc<Notify>,
}

impl PostgresNotifier {
    pub fn new(
        pool: DbPool,
        connector: impl Fn() -> Pin<
                Box<
                    dyn Future<
                            Output = Result<(Conn, Connection<Socket, NoTlsStream>), PostgresError>,
                        > + Send,
                >,
            > + Send
            + Sync
            + 'static,
    ) -> Self {
        let notify = Arc::new(Notify::new());
        {
            let notify = notify.clone();
            tokio::spawn(async move {
                loop {
                    let (conn, handle) = match connector().await {
                        Ok(x) => x,
                        Err(e) => {
                            error!("failed to get connection for postgres listen: {e}, trying again in 1 second");
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            continue;
                        }
                    };
                    match Self::notifier(conn, handle, &notify).await {
                        Ok(()) => {
                            warn!("notifier termianted, restarting in 10 seconds");
                            tokio::time::sleep(Duration::from_secs(10)).await;
                        }
                        Err(e) => {
                            error!("notifier failed: {e}, restarting in 10 seconds");
                            tokio::time::sleep(Duration::from_secs(10)).await;
                        }
                    }
                }
            });
        }
        Self { pool, notify }
    }

    async fn notifier(
        conn: Conn,
        mut handle: Connection<Socket, NoTlsStream>,
        notify: &Notify,
    ) -> Result<(), PostgresError> {
        let mut app_stream = futures::stream::poll_fn(move |cx| handle.poll_message(cx));
        let initial_listen = conn.execute(r#"LISTEN zone_update"#, &[]).fuse();
        futures::pin_mut!(initial_listen);
        info!("listening for psql notifications on 'zone_update' channel");

        loop {
            select! {
                out = &mut initial_listen => {
                    if let Err(e) = out {
                        return Err(e.into());
                    }
                    notify.notify_one();
                },
                message = app_stream.next() => {
                    match message {
                        Some(Ok(AsyncMessage::Notification(notification))) => {
                            if notification.channel() != "zone_update" {
                                continue;
                            }

                            notify.notify_one();
                        },
                        Some(Ok(_)) => (),
                        Some(Err(e)) => {
                            return Err(e.into());
                        },
                        None => break,
                    }
                },
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl NotifierSystem for PostgresNotifier {
    async fn notify(&self) -> Result<(), PostgresError> {
        let conn = self.pool.get().await?;
        conn.execute(r"NOTIFY zone_update", &[]).await?;
        Ok(())
    }

    async fn notified(&self) {
        self.notify.notified().await;
    }
}

pub struct CockroachNotifier {
    pool: DbPool,
    notify: Arc<Notify>,
}

impl CockroachNotifier {
    pub async fn new(pool: DbPool) -> Result<Self, PostgresError> {
        {
            let conn = pool.get().await?;
            conn.execute(r"CREATE TABLE IF NOT EXISTS zone_update (id INT4 PRIMARY KEY, updated_at TIMESTAMPTZ)", &[]).await?;
            conn.execute(r"INSERT INTO zone_update (id, updated_at) VALUES (1, now()) ON CONFLICT (id) DO NOTHING", &[]).await?;
        }
        let notify = Arc::new(Notify::new());
        {
            let notify = notify.clone();
            let pool = pool.clone();
            tokio::spawn(async move {
                loop {
                    let conn = match pool.dedicated_connection().await {
                        Ok(x) => x,
                        Err(e) => {
                            error!("failed to get connection for cockroachdb listen: {e}, trying again in 1 second");
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            continue;
                        }
                    };

                    match Self::notifier(conn, &notify).await {
                        Ok(()) => {
                            warn!("notifier termianted, restarting in 10 seconds");
                            tokio::time::sleep(Duration::from_secs(10)).await;
                        }
                        Err(e) => {
                            error!("notifier failed: {e}, restarting in 10 seconds");
                            tokio::time::sleep(Duration::from_secs(10)).await;
                        }
                    }
                }
            });
        }
        Ok(Self { pool, notify })
    }

    async fn notifier(conn: Conn, notify: &Notify) -> Result<(), PostgresError> {
        let stream = conn
            .query_raw::<_, &dyn ToSql, _>(
                r"EXPERIMENTAL CHANGEFEED FOR zone_update;",
                std::iter::empty(),
            )
            .await?;
        pin_mut!(stream);
        info!("listening for table updates on table zone_update");
        while let Some(message) = stream.next().await {
            let _message = message?;
            notify.notify_one();
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl NotifierSystem for CockroachNotifier {
    async fn notify(&self) -> Result<(), PostgresError> {
        let conn = self.pool.get().await?;
        conn.execute(r"UPDATE zone_update SET updated_at=now() WHERE 1=1", &[])
            .await?;
        Ok(())
    }

    async fn notified(&self) {
        self.notify.notified().await;
    }
}
