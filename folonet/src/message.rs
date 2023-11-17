use folonet_common::{
    event::{Event, Packet},
    Notification,
};

use crate::endpoint::{Connection, Endpoint};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Message {
    pub from: Endpoint,
    pub to: Endpoint,
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
                from: Endpoint::new(k_connection.from),
                to: Endpoint::new(k_connection.to),
                local_in: Endpoint::new(notification.local_in_endpoint),
                local_out: Endpoint::new(notification.lcoal_out_endpoint),
                from_client,
                msg_type,
            }
        } else {
            Message {
                from: Endpoint::new(k_connection.to),
                to: Endpoint::new(k_connection.from),
                local_in: Endpoint::new(notification.lcoal_out_endpoint),
                local_out: Endpoint::new(notification.local_in_endpoint),
                from_client,
                msg_type,
            }
        }
    }

    pub fn connection(&self) -> Connection {
        Connection {
            from: self.from,
            to: self.to,
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
