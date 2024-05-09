use std::{collections::HashMap, sync::atomic::AtomicBool};

use folonet_client::config::ServiceConfig;

use crate::{
    endpoint::Endpoint,
    message::{Message, MessageType},
    state::{BpfConnectionMap, BpfServicePortsMap, ConnectionStateMgr, PacketMsg},
    worker::{MsgHandler, MsgWorker},
};

pub struct Service {
    pub name: String,
    pub local_endpoint: Endpoint,
    pub servers: Vec<Endpoint>,
    pub active: AtomicBool,
    pub server_tracker_map: HashMap<Endpoint, MsgWorker<ConnectionStateMgr>>,
}

impl MsgHandler for Service {
    type MsgType = Message;

    async fn handle_message(&mut self, msg: Self::MsgType) {
        match msg.msg_type {
            MessageType::Packet(_) => {
                if let Some(server_tracker) = self.server_tracker_map.get_mut(&msg.server) {
                    server_tracker.handle_packet_msg(msg).await;
                }
            }
            MessageType::Close => {}
        }
    }
}

impl Service {
    pub fn new(
        cfg: &ServiceConfig,
        connection_map: BpfConnectionMap,
        service_ports_map: BpfServicePortsMap,
    ) -> Self {
        let local_endpoint = Endpoint::from(&cfg.local_endpoint);
        let servers: Vec<Endpoint> = cfg.servers.iter().map(|s| Endpoint::from(s)).collect();
        let server_tracker_map: HashMap<Endpoint, MsgWorker<ConnectionStateMgr>> = servers
            .iter()
            .map(|server| {
                (
                    server.clone(),
                    MsgWorker::new(ConnectionStateMgr::new(
                        cfg.is_tcp,
                        connection_map.clone(),
                        service_ports_map.clone(),
                    )),
                )
            })
            .collect();

        let service = Service {
            name: cfg.name.clone(),
            local_endpoint,
            servers,
            active: AtomicBool::new(false),
            server_tracker_map,
        };
        service
    }
}
