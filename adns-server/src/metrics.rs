use prometheus::{
    register_histogram_vec, register_int_counter_vec, register_int_gauge_vec, HistogramVec,
    IntCounterVec, IntGaugeVec,
};

lazy_static::lazy_static! {
    pub static ref QUERY: IntCounterVec = register_int_counter_vec!("adns_query", "count of queries received", &["ipaddr"]).unwrap();
    pub static ref QUESTIONS: IntCounterVec = register_int_counter_vec!("adns_questions", "count of questions received", &["ipaddr", "name", "class", "type"]).unwrap();
    pub static ref UPDATES: IntCounterVec = register_int_counter_vec!("adns_updates", "count of RFC2136 updates attempted/processed", &["ipaddr", "name", "class", "type", "auth"]).unwrap();
    pub static ref AXFR: IntCounterVec = register_int_counter_vec!("adns_axfr", "count of AXFR attempted", &["ipaddr", "zone", "auth"]).unwrap();
    pub static ref TCP_CONNECTIONS: IntGaugeVec = register_int_gauge_vec!("adns_connection", "inbound TCP connections", &["ipaddr"]).unwrap();
    pub static ref QUERY_US: HistogramVec = register_histogram_vec!("adns_query_us", "non-network query processing time", &[]).unwrap();
}
