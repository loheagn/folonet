use std::{
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};

use crate::tcp_fsm::{TCPInput, TCP};
use anyhow::Ok;
use folonet_common::Notification;
use log::info;
use rust_fsm::StateMachine;

pub struct EndpointState {
    tcp: Option<TcpFsmState>,
}

pub struct TcpFsmState {
    fsm: StateMachine<TCP>,
}

pub enum Direction {
    From,
    To,
}

impl EndpointState {
    pub async fn handle_notification(
        &mut self,
        notification: Notification,
        direction: Direction,
    ) -> Result<(), anyhow::Error> {
        let ip = match direction {
            Direction::From => notification.connection.from.ip(),
            Direction::To => notification.connection.to.ip(),
        };

        let ip: Ipv4Addr = u32::from_be(ip).into();
        info!("data: {}", ip.to_string());

        Ok(())
    }

    pub fn new(is_tcp: bool) -> Self {
        let tcp = if is_tcp {
            Some(TcpFsmState {
                fsm: StateMachine::new(),
            })
        } else {
            None
        };
        EndpointState { tcp }
    }
}
