use std::{
    collections::HashMap,
    sync::{atomic::AtomicBool, Arc},
};

use crate::{
    endpoint::{Endpoint, UConnection},
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
    pub state_mgr: MsgWorker<ConnectionStateMgr>,
}

impl MsgHandler for Service {
    type MsgType = Message;

    async fn handle_message(&mut self, msg: Self::MsgType) {
        match msg.msg_type {
            MessageType::Packet(_) => {
                let packet_msg = match PacketMsg::try_from(msg) {
                    Ok(packet_msg) => packet_msg,
                    Err(_) => return (),
                };

                self.state_mgr.handle_packet_msg(packet_msg).await;
            }
            MessageType::Close => {}
        }
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
        let conn_mgr = ConnectionStateMgr::new(is_tcp, connection_map);
        let state_mgr = MsgWorker::new(conn_mgr);

        let service = Service {
            name,
            local_endpoint,
            servers,
            active: AtomicBool::new(false),
            client_connection_map: HashMap::new(),
            server_connection_map: HashMap::new(),
            state_mgr,
        };
        service
    }
}
