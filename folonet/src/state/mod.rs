use folonet_common::event::Event;

use crate::endpoint::{Connection, Direction, Endpoint};

use self::{tcp::TcpStateManager, udp::UdpStateManager};

pub mod tcp;
pub mod udp;

pub enum ConnectionStateManager {
    Tcp(TcpStateManager),
    Udp(UdpStateManager),
}

impl ConnectionStateManager {
    pub fn new(is_tcp: bool) -> ConnectionStateManager {
        if is_tcp {
            ConnectionStateManager::Tcp(TcpStateManager::new())
        } else {
            ConnectionStateManager::Udp(UdpStateManager::new())
        }
    }

    pub async fn handle_packet_msg(&mut self, msg: PacketMsg) {
        match self {
            ConnectionStateManager::Tcp(tcp) => tcp.handle_packet_msg(msg).await,
            ConnectionStateManager::Udp(udp) => udp.handle_packet_msg(msg).await,
        }
    }
}

#[derive(Debug)]
pub struct PacketMsg {
    from: Endpoint,
    to: Endpoint,
    pub event: Event,
}

impl PacketMsg {
    pub fn new(connection: Connection, event: Event) -> Self {
        PacketMsg {
            from: connection.from,
            to: connection.to,
            event,
        }
    }

    pub fn direction(&self, e: &Endpoint) -> Direction {
        if e == &self.from {
            Direction::From
        } else {
            Direction::To
        }
    }

    pub fn connection(&self) -> Connection {
        Connection {
            from: self.from,
            to: self.to,
        }
    }
}
