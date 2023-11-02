use std::time::Duration;

use crate::{
    endpoint::Endpoint,
    tcp_fsm::{TCPInput, TCPState, TCP},
};
use anyhow::Ok;
use folonet_common::{
    event::{Event, Packet},
    Notification,
};
use log::info;
use rust_fsm::StateMachine;

pub struct EndpointState {
    tcp: Option<TcpFsmState>,
}

pub struct TcpFsmState {
    e: Endpoint,
    fsm: StateMachine<TCP>,
    received_special_packet: Option<SpecialPacket>,
    sent_special_packet: Option<SpecialPacket>,
}

pub enum Direction {
    From,
    To,
}

pub enum SpecialPacket {
    SYN(u32),
    FIN(u32),
}

impl EndpointState {
    pub async fn handle_notification(
        &mut self,
        notification: Notification,
        direction: Direction,
    ) -> Result<(), anyhow::Error> {
        match notification.event {
            Event::Packet(p) => self.handle_packet_event(&p, &direction).await?,
        }

        Ok(())
    }

    async fn handle_packet_event(
        &mut self,
        packet: &Packet,
        direction: &Direction,
    ) -> Result<(), anyhow::Error> {
        match self.tcp.as_mut() {
            Some(tcp) => tcp.handle_packet_event(packet, direction).await?,
            None => {}
        }

        Ok(())
    }

    pub fn new(e: &Endpoint, is_tcp: bool) -> Self {
        let mut fsm = StateMachine::<TCP>::new();
        if e.is_server_side() {
            let _ = fsm.consume(&TCPInput::PassiveOpen);
        }

        let tcp = if is_tcp {
            Some(TcpFsmState {
                fsm,
                e: *e,
                received_special_packet: None,
                sent_special_packet: None,
            })
        } else {
            None
        };
        EndpointState { tcp }
    }
}

impl TcpFsmState {
    async fn handle_packet_event(
        &mut self,
        packet: &Packet,
        direction: &Direction,
    ) -> Result<(), anyhow::Error> {
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
            info!("{} into time wait.", self.e.to_string());
            tokio::time::sleep(Duration::from_secs(60)).await;
            let _ = self.fsm.consume(&TCPInput::TimeExpired);
        }

        if self.fsm.state() == &TCPState::Closed {
            info!("{} closed.", self.e.to_string());
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
