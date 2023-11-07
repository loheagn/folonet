use std::{collections::HashMap, sync::Arc};

use aya::maps::{HashMap as AyaHashMap, MapData as AyaMapData};
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

pub struct ConnectionStateMgr {
    is_tcp: bool,
    connection_map: HashMap<Connection, L4ConnState>,
    bpf_conn_map: BpfConnectionMap, // reference the bpf map
}

impl ConnectionStateMgr {
    pub fn new(is_tcp: bool, bpf_conn_map: BpfConnectionMap) -> Self {
        ConnectionStateMgr {
            is_tcp,
            connection_map: HashMap::new(),
            bpf_conn_map,
        }
    }
}

impl MsgWorker<ConnectionStateMgr> {
    pub async fn handle_packet_msg(&mut self, msg: PacketMsg) {
        let mut conn_mgr = self.handler.lock().await;
        let is_tcp = conn_mgr.is_tcp;
        let connection_state = conn_mgr
            .connection_map
            .entry(msg.connection())
            .or_insert_with(|| {
                if is_tcp {
                    let mut conn_state = tcp::ConnectionState::new(&msg.from, &msg.to);
                    if let Some(sender) = self.msg_sender() {
                        conn_state.set_close_event_sender(sender.clone());
                    }
                    L4ConnState::from(MsgWorker::new(conn_state))
                } else {
                    L4ConnState::from(UdpConnState::new())
                }
            });
        connection_state.handle_packet(msg).await;
    }
}

impl MsgHandler for ConnectionStateMgr {
    type MsgType = Message;

    async fn handle_message(&mut self, msg: Self::MsgType) {
        match msg.msg_type {
            MessageType::Close => {
                let conn = msg.connection();
                self.connection_map.remove(&conn);

                info!("remove connection {:?}", conn);
            }
            _ => {}
        }
    }
}

#[derive(Debug)]
pub struct PacketMsg {
    from: Endpoint,
    to: Endpoint,
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

impl TryFrom<Message> for PacketMsg {
    type Error = ();
    fn try_from(msg: Message) -> Result<Self, Self::Error> {
        match msg.msg_type {
            MessageType::Packet(packet_type) => {
                let packet = match packet_type {
                    PacketMsgType::TCP(p) => Some(p),
                    PacketMsgType::UDP => None,
                };
                Ok(PacketMsg {
                    from: msg.from,
                    to: msg.to,
                    packet: packet,
                })
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
