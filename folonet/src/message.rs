use folonet_common::{
    event::{Event, Packet},
    Notification,
};

use crate::endpoint::{Connection, Endpoint, UConnection};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Message {
    pub client: Endpoint,
    pub server: Endpoint,
    pub local_in: Endpoint,
    pub local_out: Endpoint,
    pub from_client: bool,
    pub msg_type: MessageType,
}

impl Message {
    pub fn from_notification(notification: Notification, from_client: bool) -> Self {
        let msg_type = match notification.event {
            Event::TcpPacket(packet) => MessageType::Packet(PacketMsgType::TCP(packet)),
            Event::UdpPacket(_) => MessageType::Packet(PacketMsgType::UDP),
        };
        let k_connection = notification.connection;

        if from_client {
            Message {
                client: Endpoint::new(k_connection.from),
                server: Endpoint::new(k_connection.to),
                local_in: Endpoint::new(notification.local_in_endpoint),
                local_out: Endpoint::new(notification.lcoal_out_endpoint),
                from_client,
                msg_type,
            }
        } else {
            Message {
                client: Endpoint::new(k_connection.to),
                server: Endpoint::new(k_connection.from),
                local_in: Endpoint::new(notification.lcoal_out_endpoint),
                local_out: Endpoint::new(notification.local_in_endpoint),
                from_client,
                msg_type,
            }
        }
    }

    pub fn to_u_connections(&self) -> (UConnection, UConnection) {
        (
            UConnection::new(self.client, self.local_in),
            UConnection::new(self.server, self.local_out),
        )
    }

    pub fn connection(&self) -> Connection {
        Connection {
            from: self.client,
            to: self.server,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MessageType {
    Packet(PacketMsgType),
    Close,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PacketMsgType {
    TCP(Packet),
    UDP,
}
