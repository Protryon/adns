use adns_server::Server;
use config::Config;

mod config;

#[tokio::main]
async fn main() {
    env_logger::Builder::new()
        .parse_env(env_logger::Env::default().default_filter_or("info"))
        .init();
    let mut config_file = std::env::var("ADNS_CONFIG").unwrap_or_default();
    if config_file.is_empty() {
        config_file = "./config.yaml".to_string();
    }
    let config: Config = serde_yaml::from_str(
        &tokio::fs::read_to_string(&config_file)
            .await
            .expect("failed to read config file"),
    )
    .expect("failed to parse config file");
    if let Some(prometheus_bind) = config.prometheus_bind {
        prometheus_exporter::start(prometheus_bind).expect("failed to load prometheus_exporter");
    }
    let mut servers = vec![];
    for server_config in config.servers {
        servers.push(tokio::spawn(async move {
            let server = Server::new(
                server_config.udp_bind,
                server_config.tcp_bind,
                server_config.zone.construct(),
            );
            server.run().await;
        }))
    }
    futures::future::join_all(servers).await;
}
