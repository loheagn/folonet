use std::collections::HashSet;
use std::net::SocketAddr;
use std::{hash::Hash, net::Ipv4Addr};

use aya::Pod;
use folonet_common::Mac;
use folonet_common::{queue::Queue, KConnection, KEndpoint, Notification};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UEndpoint(KEndpoint);

impl UEndpoint {
    pub fn new(e: KEndpoint) -> Self {
        UEndpoint(e)
    }
}

unsafe impl Pod for UEndpoint {}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Endpoint {
    pub ip: Ipv4Addr,
    pub port: u16,
}

static mut SERVER_IP_SET: Lazy<Mutex<HashSet<u32>>> = Lazy::new(|| Mutex::new(HashSet::new()));
pub fn set_server_ip(ip: &String) {
    let ip: u32 = ip.parse::<Ipv4Addr>().unwrap().into();
    unsafe {
        let mut set = SERVER_IP_SET.try_lock().unwrap();
        set.insert(ip);
    }
}

pub fn mac_from_string(mac: &String) -> Mac {
    let mac: Vec<u8> = mac
        .split(":")
        .into_iter()
        .map(|s| u8::from_str_radix(s, 16).unwrap())
        .collect();
    let mac: [u8; 6] = mac.try_into().unwrap();
    Mac::from(mac)
}

impl Endpoint {
    pub fn is_server_side(&self) -> bool {
        let ip = u32::from(self.ip);
        unsafe { SERVER_IP_SET.try_lock().unwrap().contains(&ip) }
    }

    pub fn to_k_endpoint(&self) -> KEndpoint {
        let ip = u32::from(self.ip).to_be();
        let port = self.port.to_be();
        KEndpoint::new(ip, port)
    }

    pub fn to_u_endpoint(&self) -> UEndpoint {
        UEndpoint(self.to_k_endpoint())
    }
}

impl From<&String> for Endpoint {
    fn from(s: &String) -> Self {
        let server: SocketAddr = s.parse().unwrap();
        match server {
            SocketAddr::V4(addr) => Endpoint {
                ip: addr.ip().clone(),
                port: addr.port(),
            },
            SocketAddr::V6(_) => panic!(),
        }
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

impl UConnection {
    pub fn new(from: Endpoint, to: Endpoint) -> Self {
        UConnection(KConnection {
            from: from.to_k_endpoint(),
            to: to.to_k_endpoint(),
        })
    }
}

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

impl Into<KConnection> for Connection {
    fn into(self) -> KConnection {
        KConnection {
            from: self.from.to_k_endpoint(),
            to: self.to.to_k_endpoint(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Direction {
    From,
    To,
}

#[derive(Clone, Copy)]
pub struct UQueue<T>(Queue<T>)
where
    T: Clone + Copy + Sized + Default;

impl<T> UQueue<T>
where
    T: Clone + Copy + Sized + Default,
{
    pub fn new() -> Self {
        UQueue(Queue::new())
    }

    pub fn push(&mut self, item: T) {
        self.0.push(item);
    }

    pub fn pop(&mut self) -> T {
        self.0.pop()
    }
}

unsafe impl Pod for UQueue<u16> {}

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
