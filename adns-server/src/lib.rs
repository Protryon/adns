mod server;
pub use server::*;

mod zone_provider;
pub use zone_provider::*;

mod metrics;
pub use metrics::*;

#[cfg(feature = "postgres")]
pub mod db;

#[cfg(test)]
mod tests {
    use adns_proto::{Record, TypeData};
    use adns_zone::Zone;

    use crate::{Server, StaticZoneProvider};

    #[tokio::test]
    async fn test_server() {
        env_logger::Builder::new()
            .parse_env(env_logger::Env::default().default_filter_or("info"))
            .init();
        Server::new(
            "0.0.0.0:5053".parse().unwrap(),
            "0.0.0.0:5053".parse().unwrap(),
            StaticZoneProvider(Zone {
                authoritative: false,
                tsig_keys: Default::default(),
                records: vec![Record::new(
                    "example.com".parse().unwrap(),
                    300,
                    TypeData::A("123.123.123.123".parse().unwrap()),
                )],
                soa: None,
                nameservers: vec![],
                zones: Default::default(),
                class: Default::default(),
                allow_md5_tsig: false,
            }),
        )
        .run()
        .await;
    }
}
