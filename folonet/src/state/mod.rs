use std::collections::HashMap;

use enum_dispatch::enum_dispatch;
use folonet_common::event::Event;

use crate::endpoint::{Connection, Direction, Endpoint};

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

pub struct ConnectionStateMgr {
    is_tcp: bool,
    connection_map: HashMap<Connection, L4ConnState>,
}

impl ConnectionStateMgr {
    pub fn new(is_tcp: bool) -> Self {
        ConnectionStateMgr {
            is_tcp,
            connection_map: HashMap::new(),
        }
    }

    pub async fn handle_packet_msg(&mut self, msg: PacketMsg) {
        let connection_state = self
            .connection_map
            .entry(msg.connection())
            .or_insert_with(|| {
                if self.is_tcp {
                    L4ConnState::from(TcpConnState::from_connection(&msg.connection()))
                } else {
                    L4ConnState::from(UdpConnState::new())
                }
            });
        connection_state.handle_packet(msg).await;
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
