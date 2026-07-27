/// Spec §11.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ConnectionState {
    #[default]
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Failed,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnectionStats {
    pub state: ConnectionState,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub active_flows: u32,
    pub flows_failed: u64,
    /// Non-DNS UDP datagrams discarded. Spec §7.5 — counted, never silent.
    pub udp_dropped: u64,
    pub dns_queries: u64,
    pub reconnects: u32,
}
