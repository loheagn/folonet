use async_trait::async_trait;
use aya::maps::{HashMap as AyaHashMap, MapData as AyaMapData};
use folonet_common::{event::Event, Notification};
use std::{
    collections::HashMap,
    sync::{atomic::AtomicBool, Arc},
};

use crate::{
    endpoint::{Connection, Endpoint, UConnection},
    state::{ConnectionStateManager, PacketMsg},
    worker::MsgHandler,
};

#[derive(Debug, Clone)]
pub struct Message(Notification);

impl Message {
    pub fn new(notification: Notification) -> Self {
        Self(notification)
    }

    pub fn connection(&self) -> Connection {
        let k_connection = self.0.connection;
        Connection {
            from: Endpoint::new(k_connection.from),
            to: Endpoint::new(k_connection.to),
        }
    }
}

pub type BpfConnectionMap =
    Arc<tokio::sync::Mutex<AyaHashMap<AyaMapData, UConnection, UConnection>>>;

pub struct Service {
    pub name: String,
    pub local_endpoint: Endpoint,
    pub servers: Vec<Endpoint>,
    pub active: AtomicBool,
    pub client_connection_map: HashMap<Endpoint, Endpoint>,
    pub server_connection_map: HashMap<Endpoint, Endpoint>,
    pub state_mgr: ConnectionStateManager,

    pub connection_map: BpfConnectionMap, // reference the bpf map
}

#[async_trait]
impl MsgHandler for Service {
    type MsgType = Message;

    async fn handle_message(&mut self, msg: Self::MsgType) {
        let notification = msg.0;
        match notification.event {
            Event::TcpPacket(_) | Event::UdpPacket => {
                let msg = PacketMsg::new(msg.connection(), notification.event);
                self.state_mgr.handle_packet_msg(msg).await;
            }
        };
    }
}

impl Service {
    pub fn new(
        name: String,
        local_endpoint: Endpoint,
        servers: Vec<Endpoint>,
        is_tcp: bool,
        connection_map: BpfConnectionMap,
    ) -> Self {
        let state_mgr = ConnectionStateManager::new(is_tcp);
        let service = Service {
            name,
            local_endpoint,
            servers,
            active: AtomicBool::new(false),
            client_connection_map: HashMap::new(),
            server_connection_map: HashMap::new(),
            state_mgr,
            connection_map,
        };
        service
    }
}
