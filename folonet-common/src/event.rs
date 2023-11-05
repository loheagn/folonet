use bitflags::bitflags;
use network_types::tcp::TcpHdr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]

pub enum Event {
    Packet(Packet),
    Udp,
}

impl Event {
    pub fn type_id(&self) -> u8 {
        match self {
            Event::Packet(_) => 1,
            Event::Udp => 2,
        }
    }

    pub fn new_packet_event(tcphdr: *const TcpHdr) -> Self {
        let packet = Packet::new(&unsafe { *tcphdr });
        Event::Packet(packet)
    }
}

impl From<&Event> for u128 {
    fn from(e: &Event) -> u128 {
        match e {
            Event::Packet(ref p) => (e.type_id() as u128) << 120 | u128::from(p),
            Event::Udp => 0,
        }
    }
}

impl From<u128> for Event {
    fn from(v: u128) -> Self {
        let type_id = (v >> 120) as u8;
        match type_id {
            1 => Event::Packet(Packet::from(v)),
            _ => panic!("unknown event type id: {}", type_id),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Packet {
    pub flag: PacketFlag,
    pub ack_seq: u32,
    pub seq: u32,
}

impl Packet {
    pub fn new(tcphdr: &TcpHdr) -> Self {
        let mut flag = PacketFlag::empty();
        if tcphdr.syn() != 0 {
            flag.insert(PacketFlag::SYN);
        }
        if tcphdr.fin() != 0 {
            flag.insert(PacketFlag::FIN);
        }
        if tcphdr.ack() != 0 {
            flag.insert(PacketFlag::ACK);
        }
        Packet {
            flag,
            ack_seq: u32::from_be(tcphdr.ack_seq),
            seq: u32::from_be(tcphdr.seq),
        }
    }

    pub fn is_syn(&self) -> bool {
        return self.flag.contains(PacketFlag::SYN);
    }

    pub fn is_fin(&self) -> bool {
        return self.flag.contains(PacketFlag::FIN);
    }

    pub fn is_ack(&self) -> bool {
        return self.flag.contains(PacketFlag::ACK);
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct PacketFlag: u32 {
         const SYN = 0b0000_0001;
         const FIN = 0b0000_0010;
         const ACK = 0b0000_0100;
    }
}

impl From<u128> for Packet {
    fn from(value: u128) -> Self {
        let ack_seq = ((value as u64) >> 32) as u32;
        let seq = value as u32;
        let flag = PacketFlag::from_bits_truncate((value >> 64) as u32);
        Packet { flag, ack_seq, seq }
    }
}

impl From<&Packet> for u128 {
    fn from(value: &Packet) -> Self {
        value.into()
    }
}

mod test {

    #[test]
    fn test_packet() {
        use super::{Packet, PacketFlag};
        let p = Packet {
            flag: PacketFlag::ACK | PacketFlag::SYN,
            ack_seq: 128,
            seq: 129,
        };

        let v: u128 = (&p).into();

        let got_p: Packet = v.into();

        assert_eq!(p, got_p);
    }
}
