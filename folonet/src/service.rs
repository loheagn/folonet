use std::{
    collections::HashMap,
    hash::Hash,
    sync::{atomic::AtomicBool, Arc},
};

use crate::{
    config::ServiceConfig,
    endpoint::{Connection, Endpoint, UConnection},
    message::{Message, MessageType},
    state::{BpfConnectionMap, ConnectionStateMgr, PacketMsg},
    worker::{MsgHandler, MsgWorker},
};

pub struct Service {
    pub name: String,
    pub local_endpoint: Endpoint,
    pub servers: Vec<Endpoint>,
    pub active: AtomicBool,
    pub client_connection_map: HashMap<Endpoint, Endpoint>,
    pub server_connection_map: HashMap<Endpoint, Endpoint>,
    pub server_tracker_map: HashMap<Endpoint, MsgWorker<ConnectionStateMgr>>,
}

impl MsgHandler for Service {
    type MsgType = Message;

    async fn handle_message(&mut self, msg: Self::MsgType) {
        match msg.msg_type {
            MessageType::Packet(_) => {
                let packet_msg = match PacketMsg::try_from(&msg) {
                    Ok(packet_msg) => packet_msg,
                    Err(_) => return (),
                };

                if let Some(server_tracker) = self.server_tracker_map.get_mut(&msg.to) {
                    server_tracker.handle_packet_msg(packet_msg).await;
                }
            }
            MessageType::Close => {}
        }
    }
}

impl Service {
    pub fn new(cfg: &ServiceConfig, connection_map: BpfConnectionMap) -> Self {
        let local_endpoint = Endpoint::from(&cfg.local_endpoint);
        let servers: Vec<Endpoint> = cfg.servers.iter().map(|s| Endpoint::from(s)).collect();
        let server_tracker_map: HashMap<Endpoint, MsgWorker<ConnectionStateMgr>> = servers
            .iter()
            .map(|server| {
                (
                    server.clone(),
                    MsgWorker::new(ConnectionStateMgr::new(cfg.is_tcp, connection_map.clone())),
                )
            })
            .collect();

        let service = Service {
            name: cfg.name.clone(),
            local_endpoint,
            servers,
            active: AtomicBool::new(false),
            client_connection_map: HashMap::new(),
            server_connection_map: HashMap::new(),
            server_tracker_map,
        };
        service
    }
}
