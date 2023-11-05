use std::{hash::Hash, net::Ipv4Addr};

use aya::Pod;
use folonet_common::{KConnection, KEndpoint, Notification, SERVER_IP};
use log::info;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UEndpoint(KEndpoint);

impl UEndpoint {
    pub fn new(e: KEndpoint) -> Self {
        UEndpoint(e)
    }

    pub fn to_k_endpoint(&self) -> KEndpoint {
        self.0
    }
}

unsafe impl Pod for UEndpoint {}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
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
pub struct UConnection(KConnection);

unsafe impl Pod for UConnection {}

#[derive(Clone, Copy, Debug, Eq)]
pub struct Connection {
    pub from: Endpoint,
    pub to: Endpoint,
}

impl PartialEq for Connection {
    fn eq(&self, other: &Self) -> bool {
        (self.from == other.from && self.to == other.to)
            || (self.to == other.from && self.from == other.to)
    }
}

impl Hash for Connection {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let a = self.from;
        let b = self.to;
        if a > b {
            a.hash(state);
            b.hash(state);
        } else {
            b.hash(state);
            a.hash(state);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Direction {
    From,
    To,
}

mod test {

    #[test]
    fn test_connection_map() {
        use std::{collections::HashMap, net::Ipv4Addr};

        use super::{Connection, Endpoint};

        let endpoint1 = Endpoint {
            ip: Ipv4Addr::new(1, 2, 3, 4),
            port: 80,
        };
        let endpoint2 = Endpoint {
            ip: Ipv4Addr::new(4, 2, 3, 4),
            port: 89,
        };

        let connection = Connection {
            from: endpoint1,
            to: endpoint2,
        };

        let other_connection = Connection {
            from: endpoint2,
            to: endpoint1,
        };

        let map = HashMap::from([(connection, 2)]);

        assert_eq!(connection.from, other_connection.to);
        assert_eq!(connection.to, other_connection.from);

        assert!(connection == other_connection);

        let self3 = &connection;
        let other = &other_connection;
        assert!(
            (self3.from == other.from && self3.to == other.to)
                || (self3.to == other.from && self3.from == other.to)
        );

        assert!(map.get(&connection).is_some());

        assert!(map.get(&other_connection).is_some());
    }
}
