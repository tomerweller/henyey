use async_trait::async_trait;

use crate::connection::{Connection, Listener};
use crate::{PeerAddress, Result};

#[async_trait]
pub trait ConnectionFactory: Send + Sync {
    async fn connect(&self, addr: &PeerAddress, timeout_secs: u64) -> Result<Connection>;

    async fn bind(&self, port: u16) -> Result<Listener>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct TcpConnectionFactory;

#[async_trait]
impl ConnectionFactory for TcpConnectionFactory {
    async fn connect(&self, addr: &PeerAddress, timeout_secs: u64) -> Result<Connection> {
        Connection::connect(addr, timeout_secs).await
    }

    async fn bind(&self, port: u16) -> Result<Listener> {
        Listener::bind(port).await
    }
}
