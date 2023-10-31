use std::net::Ipv4Addr;

use aya::Pod;
use folonet_common::{KConnection, KEndpoint, Notification};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Endpoint(KEndpoint);

unsafe impl Pod for Endpoint {}

impl Endpoint {
    pub fn ip(&self) -> Ipv4Addr {
        u32::from_be(self.0.ip()).into()
    }

    pub fn port(&self) -> u16 {
        u16::from_be(self.port())
    }
}

impl Endpoint {
    pub fn new(endpoint: KEndpoint) -> Self {
        Endpoint(endpoint)
    }
}

pub fn endpoint_pair_from_notification(notification: &Notification) -> (Endpoint, Endpoint) {
    (
        Endpoint::new(notification.connection.from),
        Endpoint::new(notification.connection.to),
    )
}

#[derive(Clone, Copy, Debug)]
pub struct Connection(KConnection);

unsafe impl Pod for Connection {}
