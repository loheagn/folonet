use std::{
    collections::HashMap,
    hash::Hash,
    sync::{atomic::AtomicBool, Arc},
};

use aya::maps::{HashMap as AyaHashMap, MapData as AyaMapData, Queue};
use enum_dispatch::enum_dispatch;
use folonet_common::event::Packet;
use log::info;
use tokio::sync::mpsc;

use crate::{
    endpoint::{Connection, Direction, Endpoint, UConnection},
    message::{Message, MessageType, PacketMsgType},
    worker::{MsgHandler, MsgWorker},
};

use self::{tcp::TcpConnState, udp::UdpConnState};

pub mod tcp;
pub mod udp;

#[enum_dispatch]
pub trait PacketHandler: Send + Sync + 'static {
    async fn handle_packet(&mut self, packet: PacketMsg);
}

#[enum_dispatch(PacketHandler)]
enum L4ConnState {
    TcpConnState,
    UdpConnState,
}

pub type BpfConnectionMap =
    Arc<tokio::sync::Mutex<AyaHashMap<AyaMapData, UConnection, UConnection>>>;

pub type BpfServicePortsMap = Arc<tokio::sync::Mutex<Queue<AyaMapData, u16>>>;

pub struct ConnectionStateMgr {
    is_tcp: bool,
    is_active: AtomicBool,
    state_map: HashMap<Connection, L4ConnState>,
    port_map: HashMap<Connection, u16>,
    connection_msp: HashMap<Connection, (UConnection, UConnection)>,

    bpf_conn_map: BpfConnectionMap, // reference the bpf map
    bpf_service_ports_map: BpfServicePortsMap,
}

impl ConnectionStateMgr {
    pub fn new(
        is_tcp: bool,
        bpf_conn_map: BpfConnectionMap,
        bpf_service_ports_map: BpfServicePortsMap,
    ) -> Self {
        ConnectionStateMgr {
            is_tcp,
            is_active: AtomicBool::new(false),
            state_map: HashMap::new(),
            port_map: HashMap::new(),
            connection_msp: HashMap::new(),
            bpf_conn_map,
            bpf_service_ports_map,
        }
    }
}

impl MsgWorker<ConnectionStateMgr> {
    pub async fn handle_packet_msg(&mut self, msg: Message) {
        let packet_msg = PacketMsg::try_from(&msg);
        if packet_msg.is_err() {
            return;
        }
        let packet_msg = packet_msg.unwrap();
        let local_out_port = packet_msg.local_out_port;
        let conn = packet_msg.connection();
        {
            let mut conn_mgr = self.handler.lock().await;
            let is_tcp = conn_mgr.is_tcp;

            let state_map = &mut conn_mgr.state_map;
            let connection_state = state_map.entry(conn.clone()).or_insert_with(|| {
                if is_tcp {
                    let mut conn_state =
                        tcp::ConnectionState::new(&packet_msg.from, &packet_msg.to);
                    if let Some(sender) = self.msg_sender() {
                        conn_state.set_close_event_sender(sender.clone());
                    }
                    L4ConnState::from(MsgWorker::new(conn_state))
                } else {
                    L4ConnState::from(UdpConnState::new())
                }
            });
            connection_state.handle_packet(packet_msg).await;
        }
        {
            // record port
            let mut conn_mgr = self.handler.lock().await;
            let port_map = &mut conn_mgr.port_map;
            if !port_map.contains_key(&conn) {
                port_map.insert(conn.clone(), local_out_port);
            }
        }

        {
            // record connections
            let mut conn_mgr = self.handler.lock().await;
            conn_mgr
                .connection_msp
                .insert(conn.clone(), msg.to_u_connections());
        }
    }
}

impl MsgHandler for ConnectionStateMgr {
    type MsgType = CloseMsg;

    async fn handle_message(&mut self, msg: Self::MsgType) {
        let conn = msg.connection();
        let _ = self.state_map.remove(&conn);

        let port = self.port_map.remove(&conn);
        if let Some(port) = port {
            let mut ports_map = self.bpf_service_ports_map.lock().await;
            ports_map.push(port, 0).unwrap();
        }

        let u_connections = self.connection_msp.remove(&conn);
        if let Some(u_conns) = u_connections {
            let mut conn_map = self.bpf_conn_map.lock().await;
            conn_map.remove(&u_conns.0).unwrap();
            conn_map.remove(&u_conns.1).unwrap();
        }

        info!("remove connection {:?}", conn);
    }
}

#[derive(Debug)]
pub struct CloseMsg {
    from: Endpoint,
    to: Endpoint,
}

impl CloseMsg {
    pub fn new(from: Endpoint, to: Endpoint) -> Self {
        CloseMsg { from, to }
    }

    fn connection(&self) -> Connection {
        Connection {
            from: self.from,
            to: self.to,
        }
    }
}

#[derive(Debug)]
pub struct PacketMsg {
    from: Endpoint,
    to: Endpoint,
    local_out_port: u16,
    pub packet: Option<Packet>,
}

impl PacketMsg {
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

impl TryFrom<&Message> for PacketMsg {
    type Error = ();
    fn try_from(msg: &Message) -> Result<Self, Self::Error> {
        match &msg.msg_type {
            MessageType::Packet(packet_type) => {
                let packet = match packet_type {
                    PacketMsgType::TCP(p) => Some(p.clone()),
                    PacketMsgType::UDP => None,
                };
                let packet_msg = if msg.from_client {
                    PacketMsg {
                        from: msg.client,
                        to: msg.server,
                        local_out_port: msg.local_out.port,
                        packet,
                    }
                } else {
                    PacketMsg {
                        from: msg.server,
                        to: msg.client,
                        local_out_port: msg.local_out.port,
                        packet,
                    }
                };
                Ok(packet_msg)
            }
            _ => return Err(()),
        }
    }
}

mod test {

    #[test]
    fn test_generic_reture() {
        use enum_dispatch::enum_dispatch;
        use log::info;

        #[enum_dispatch]
        trait Trait {
            fn echo(&self);
        }
        struct A {}
        struct B {}
        impl Trait for A {
            fn echo(&self) {
                info!("a");
            }
        }
        impl Trait for B {
            fn echo(&self) {
                info!("b");
            }
        }

        #[enum_dispatch(Trait)]
        enum AB {
            A,
            B,
        }

        struct Test {
            t: AB,
        }

        impl Test {
            fn echo(&self) {
                self.t.echo();
            }
        }

        fn test_echo(is_a: bool) {
            let t = if is_a {
                let t = AB::from(A {});
                Test { t }
            } else {
                let t = AB::from(B {});
                Test { t }
            };

            t.echo();
        }

        test_echo(true);
        test_echo(false);
    }
}
