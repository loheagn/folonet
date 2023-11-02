use std::net::Ipv4Addr;

use aya::Pod;
use folonet_common::{KConnection, KEndpoint, Notification, SERVER_IP};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UEndpoint(KEndpoint);

impl UEndpoint {
    pub fn new(e: KEndpoint) -> Self {
        UEndpoint(e)
    }
}

unsafe impl Pod for UEndpoint {}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Endpoint {
    pub ip: Ipv4Addr,
    pub port: u16,
}

impl Endpoint {
    pub fn is_server_side(&self) -> bool {
        let ip = u32::from(self.ip);

        ip == SERVER_IP
    }
}

impl ToString for Endpoint {
    fn to_string(&self) -> String {
        format!("{}:{}", self.ip, self.port)
    }
}

impl Endpoint {
    pub fn new(endpoint: KEndpoint) -> Self {
        Endpoint {
            ip: u32::from_be(endpoint.ip()).into(),
            port: u16::from_be(endpoint.port()),
        }
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
