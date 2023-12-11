use std::time::Duration;

use anyhow::Ok;
use folonet_common::event::Packet;
use log::{debug, info};
use rust_fsm::*;
use tokio::sync::mpsc;

use crate::{
    endpoint::{Connection, Direction, Endpoint},
    message::Message,
    worker::{MsgHandler, MsgWorker},
};

use super::{CloseMsg, PacketHandler, PacketMsg};

state_machine! {
    derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)

    pub TCP(Closed)

    Closed => {
        PassiveOpen => Listen,
        SendSyn => SynSent,
    },

    Listen(ReceiveSyn) => ListenReceiveSyn,
    ListenReceiveSyn(SendSynAck) => SynReceived,

    SynSent => {
        ReceiveSyn => SynSentReceiveSyn,
        ReceiveSynAck => ReceiveSynAckReceiveSynAck,
    },
    SynSentReceiveSyn(SendAckForSyn) => SynReceived,
    ReceiveSynAckReceiveSynAck(SendAckForSyn) => Established,

    SynReceived(RecvAckForSyn) => Established,

    Established => {
        SendFin => FinWait1,
        ReceiveFin => CloseWait,
    },

    CloseWait(SendFin) => LastAck,

    LastAck(RecvAckForFin) => Closed,

    FinWait1 => {
        RecvAckForFin => FinWait2,
        ReceiveFin => FinWait1ReceiveFin,
    },
    FinWait1ReceiveFin(SendAckForFin) => Closing,

    FinWait2(ReceiveFin) =>  FinWait2ReceiveFin,
    FinWait2ReceiveFin(SendAckForFin) => TimeWait,

    Closing(RecvAckForFin) => TimeWait,

    TimeWait(TimeExpired) => Closed,
}

pub enum SpecialPacket {
    SYN(u32),
    FIN(u32),
}
pub struct ConnectionState {
    client: TcpFsmState,
    server: TcpFsmState,

    close_event_sender: Option<mpsc::Sender<CloseMsg>>,
}

impl ConnectionState {
    pub fn new(from: &Endpoint, to: &Endpoint) -> Self {
        ConnectionState {
            client: TcpFsmState::new(from),
            server: TcpFsmState::new(to),
            close_event_sender: None,
        }
    }

    pub fn set_close_event_sender(&mut self, sender: mpsc::Sender<CloseMsg>) {
        self.close_event_sender.replace(sender);
    }
}

impl MsgHandler for ConnectionState {
    type MsgType = PacketMsg;

    async fn handle_message(&mut self, msg: PacketMsg) {
        let _ = self.client.handle_packet_event(&msg).await;
        let _ = self.server.handle_packet_event(&msg).await;

        if self.client.is_closed() && self.server.is_closed() {
            if let Some(sender) = &self.close_event_sender {
                let _ = sender.send(CloseMsg::new(msg.from, msg.to)).await;
            }
        }
    }
}

pub type TcpConnState = MsgWorker<ConnectionState>;

impl PacketHandler for TcpConnState {
    async fn handle_packet(&mut self, packet: PacketMsg) {
        if let Some(sender) = self.msg_sender() {
            let _ = sender.send(packet).await;
        }
    }
}

impl TcpConnState {
    pub fn from_connection(conn: &Connection) -> Self {
        TcpConnState::new(ConnectionState::new(&conn.from, &conn.to))
    }
}

pub struct TcpFsmState {
    e: Endpoint,
    fsm: StateMachine<TCP>,
    received_special_packet: Option<SpecialPacket>,
    sent_special_packet: Option<SpecialPacket>,
}

impl TcpFsmState {
    pub fn new(e: &Endpoint) -> Self {
        let mut fsm = StateMachine::<TCP>::new();
        if e.is_server_side() {
            let _ = fsm.consume(&TCPInput::PassiveOpen);
        }
        TcpFsmState {
            e: *e,
            fsm,
            received_special_packet: None,
            sent_special_packet: None,
        }
    }

    fn is_closed(&self) -> bool {
        self.fsm.state() == &TCPState::Closed
    }

    pub async fn handle_packet_event(&mut self, msg: &PacketMsg) -> Result<(), anyhow::Error> {
        let packet = match msg.packet {
            Some(p) => p,
            _ => return Ok(()),
        };

        let direction = msg.direction(&self.e);

        info!(
            "endpoint {} connection state handles packet: {:?}, direction: {:?}",
            self.e.to_string(),
            packet,
            direction,
        );

        self.check_input(&packet, &direction).iter().for_each(|e| {
            let old_state = self.fsm.state().clone();

            let _ = self.fsm.consume(e);

            info!(
                "{} input: {:?}, from {:?} to {:?}",
                self.e.to_string(),
                e,
                old_state,
                self.fsm.state()
            )
        });

        // last, we reord the special packet
        let special_packet = if packet.is_fin() {
            Some(SpecialPacket::FIN(packet.seq))
        } else if packet.is_syn() {
            Some(SpecialPacket::SYN(packet.seq))
        } else {
            None
        };

        if let Some(special_packet) = special_packet {
            match direction {
                Direction::From => {
                    self.sent_special_packet.replace(special_packet);
                }
                Direction::To => {
                    self.received_special_packet.replace(special_packet);
                }
            }
        }

        if self.fsm.state() == &TCPState::TimeWait {
            debug!("{} into time wait.", self.e.to_string());
            // tokio::time::sleep(Duration::from_secs(5)).await;
            let _ = self.fsm.consume(&TCPInput::TimeExpired);
        }

        if self.fsm.state() == &TCPState::Closed {
            debug!("{} closed.", self.e.to_string());
        }

        Ok(())
    }

    #[inline(always)]
    fn check_input(&self, packet: &Packet, direction: &Direction) -> Vec<TCPInput> {
        match direction {
            Direction::From => self.check_send_input(packet),
            Direction::To => self.check_receive_input(packet),
        }
    }

    #[inline(always)]
    fn check_receive_input(&self, packet: &Packet) -> Vec<TCPInput> {
        let mut inputs = vec![];

        if packet.is_ack() {
            match self.sent_special_packet {
                Some(SpecialPacket::FIN(seq)) => {
                    if seq + 1 == packet.ack_seq {
                        inputs.push(TCPInput::RecvAckForFin);
                    }
                }
                Some(SpecialPacket::SYN(seq)) => {
                    if seq + 1 == packet.ack_seq {
                        if packet.is_syn() {
                            inputs.push(TCPInput::ReceiveSynAck);
                        } else {
                            inputs.push(TCPInput::RecvAckForSyn);
                        }
                    }
                }
                None => {}
            }
        }

        if packet.is_fin() {
            inputs.push(TCPInput::ReceiveFin);
        }

        if packet.is_syn() {
            inputs.push(TCPInput::ReceiveSyn);
        }

        inputs
    }

    #[inline(always)]
    fn check_send_input(&self, packet: &Packet) -> Vec<TCPInput> {
        let mut inputs = vec![];

        if packet.is_ack() {
            match self.received_special_packet {
                Some(SpecialPacket::FIN(seq)) => {
                    if seq + 1 == packet.ack_seq {
                        inputs.push(TCPInput::SendAckForFin);
                    }
                }
                Some(SpecialPacket::SYN(seq)) => {
                    if seq + 1 == packet.ack_seq {
                        inputs.push(TCPInput::SendAckForSyn);
                    }
                }
                None => {}
            }
        }

        if packet.is_syn() {
            if packet.is_ack() {
                inputs.push(TCPInput::SendSynAck);
            } else {
                inputs.push(TCPInput::SendSyn);
            }
        }

        if packet.is_fin() {
            inputs.push(TCPInput::SendFin);
        }

        inputs
    }
}
