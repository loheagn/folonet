use tokio::sync::mpsc;

use crate::message::Message;

use super::{PacketHandler, PacketMsg};

pub struct UdpConnState {}

impl UdpConnState {
    pub fn new() -> Self {
        todo!()
    }
}

impl PacketHandler for UdpConnState {
    async fn handle_packet(&mut self, _packet: PacketMsg) {
        todo!()
    }
}
