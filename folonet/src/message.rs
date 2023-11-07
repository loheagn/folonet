use folonet_common::{
    event::{Event, Packet},
    Notification,
};

use crate::endpoint::{Connection, Endpoint};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Message {
    pub from: Endpoint,
    pub to: Endpoint,
    pub msg_type: MessageType,
}

impl Message {
    pub fn from_notification(notification: Notification) -> Self {
        let msg_type = match notification.event {
            Event::TcpPacket(packet) => MessageType::Packet(PacketMsgType::TCP(packet)),
            Event::UdpPacket(_) => MessageType::Packet(PacketMsgType::UDP),
        };
        let k_connection = notification.connection;
        Message {
            from: Endpoint::new(k_connection.from),
            to: Endpoint::new(k_connection.to),
            msg_type,
        }
    }

    pub fn close_msg(from: Endpoint, to: Endpoint) -> Self {
        let msg_type = MessageType::Close;
        Message { from, to, msg_type }
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
