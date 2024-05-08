#![no_std]

use byteorder::{BigEndian, ByteOrder};
use event::Event;
use network_types::{tcp::TcpHdr, udp::UdpHdr};

pub mod event;
pub mod maps;
pub mod queue;

pub const PORTS_QUEUE_SIZE: u32 = 50000;

pub enum L4Hdr {
    TcpHdr(*mut TcpHdr),
    UdpHdr(*mut UdpHdr),
}

impl From<*mut TcpHdr> for L4Hdr {
    fn from(value: *mut TcpHdr) -> Self {
        Self::TcpHdr(value)
    }
}

impl From<*mut UdpHdr> for L4Hdr {
    fn from(value: *mut UdpHdr) -> Self {
        Self::UdpHdr(value)
    }
}

impl L4Hdr {
    pub fn get_check(&self) -> u16 {
        match self {
            L4Hdr::TcpHdr(hdr) => unsafe { (**hdr).check },
            L4Hdr::UdpHdr(hdr) => unsafe { (**hdr).check },
        }
    }

    pub fn set_check(&self, new_csum: u16) {
        match self {
            L4Hdr::TcpHdr(hdr) => unsafe { (**hdr).check = new_csum },
            L4Hdr::UdpHdr(hdr) => unsafe { (**hdr).check = new_csum },
        }
    }

    pub fn get_source(&self) -> u16 {
        match self {
            L4Hdr::TcpHdr(hdr) => unsafe { (**hdr).source },
            L4Hdr::UdpHdr(hdr) => unsafe { (**hdr).source },
        }
    }

    pub fn get_dest(&self) -> u16 {
        match self {
            L4Hdr::TcpHdr(hdr) => unsafe { (**hdr).dest },
            L4Hdr::UdpHdr(hdr) => unsafe { (**hdr).dest },
        }
    }

    pub fn set_bi_port(&self, bi_port: &BiPort) {
        let (src, dst) = bi_port.split_net();
        match self {
            L4Hdr::TcpHdr(hdr) => unsafe {
                (**hdr).source = src;
                (**hdr).dest = dst;
            },
            L4Hdr::UdpHdr(hdr) => unsafe {
                (**hdr).source = src;
                (**hdr).dest = dst;
            },
        }
    }

    pub fn inner_tcp_ptr(&self) -> Option<*mut TcpHdr> {
        match self {
            L4Hdr::TcpHdr(hdr) => Some(*hdr),
            _ => None,
        }
    }

    pub fn is_fin(&self) -> bool {
        match self {
            L4Hdr::TcpHdr(hdr) => unsafe { (**hdr).fin() != 0 },
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BiPort(u32);

impl BiPort {
    pub fn new(src_port: u16, dst_port: u16) -> Self {
        BiPort((src_port as u32) << 16 | dst_port as u32)
    }

    pub fn split_net(&self) -> (u16, u16) {
        ((self.0 >> 16) as u16, self.0 as u16)
    }
}

impl Into<u32> for BiPort {
    fn into(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KConnection {
    pub from: KEndpoint,
    pub to: KEndpoint,
}

impl KConnection {
    pub fn reverse(&self) -> Self {
        KConnection {
            from: self.to,
            to: self.from,
        }
    }
}

pub fn csum_fold_helper(csum: u64) -> u16 {
    let mut csum = csum;

    // we cannot use loop in ebpf

    if csum >> 16 != 0 {
        csum = (csum & 0xFFFF) + (csum >> 16);
    }
    if csum >> 16 != 0 {
        csum = (csum & 0xFFFF) + (csum >> 16);
    }
    if csum >> 16 != 0 {
        csum = (csum & 0xFFFF) + (csum >> 16);
    }
    if csum >> 16 != 0 {
        csum = (csum & 0xFFFF) + (csum >> 16);
    }
    if csum >> 16 != 0 {
        csum = (csum & 0xFFFF) + (csum >> 16);
    }

    !csum as u16
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KEndpoint(u64);

impl KEndpoint {
    pub fn new(ip: u32, port: u16) -> Self {
        let val = (port as u64) << 32 | ip as u64;
        KEndpoint(val)
    }

    pub fn ip(&self) -> u32 {
        self.0 as u32
    }

    pub fn port(&self) -> u16 {
        (self.0 >> 32) as u16
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Mac(u64);

impl Mac {
    pub fn new(addr: &[u8; 6]) -> Self {
        let high = u16::from_be_bytes(addr[..2].try_into().unwrap());
        let low: u32 = u32::from_be_bytes(addr[2..].try_into().unwrap());
        let val = (high as u64) << 32 | (low as u64);
        Mac(val)
    }

    pub fn val(&self) -> u64 {
        self.0
    }
}

impl From<&[u8; 6]> for Mac {
    fn from(value: &[u8; 6]) -> Self {
        Mac::new(value)
    }
}

impl From<[u8; 6]> for Mac {
    fn from(value: [u8; 6]) -> Self {
        Mac::new(&value)
    }
}

impl Into<[u8; 6]> for Mac {
    fn into(self) -> [u8; 6] {
        let mut arr = [0u8; 8];
        BigEndian::write_u64(&mut arr, self.0);
        arr[2..].try_into().unwrap()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Notification {
    pub local_in_endpoint: KEndpoint,
    pub lcoal_out_endpoint: KEndpoint,
    pub connection: KConnection,
    pub event: Event,
}

pub const NOTIFICATION_SIZE: usize = core::mem::size_of::<Notification>();

impl Notification {
    pub fn from_bytes(bs: &[u8]) -> Self {
        unsafe { *core::mem::transmute::<*const u8, *const Notification>(bs.as_ptr()) }.clone()
    }

    pub fn is_tcp(&self) -> bool {
        match self.event {
            Event::TcpPacket(_) => true,
            Event::UdpPacket(_) => false,
        }
    }
}

mod test {
    const fn build_ip_u32(a: i32, b: i32, c: i32, d: i32) -> u32 {
        ((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32)
    }

    #[test]
    fn test_mac_from_into() {
        use crate::Mac;

        let addr: [u8; 6] = [0x1, 0x2, 0x3, 0x4, 0x5, 0x6];
        let mac: Mac = addr.into();
        let new_addr: [u8; 6] = mac.into();

        assert_eq!(new_addr, addr);
    }

    #[test]
    fn test_endpoint() {
        use crate::KEndpoint;

        let ip = build_ip_u32(192, 168, 174, 140);
        let port: u16 = 80;
        let endpoint = KEndpoint::new(ip.to_be(), port.to_be());

        assert_eq!(ip.to_be(), endpoint.ip());
        assert_eq!(port.to_be(), endpoint.port());
    }

    #[test]
    fn test_bi_port() {
        use crate::BiPort;

        let src_port = 8899u16.to_be();
        let dst_port = 80u16.to_be();

        let p = BiPort::new(src_port, dst_port);

        let (sp, dp) = p.split_net();

        assert_eq!(src_port, sp);
        assert_eq!(dst_port, dp);
    }

    #[test]
    fn test_notification_align() {
        use crate::Notification;

        assert_eq!(8 % core::mem::align_of::<Notification>(), 0);
    }

    #[test]
    fn test_notification_write_read_bytes() {
        use crate::{
            event::{Event, Packet, PacketFlag},
            KConnection, KEndpoint, Notification,
        };

        let ip = build_ip_u32(192, 168, 174, 140);
        let port: u16 = 80;
        let endpoint = KEndpoint::new(ip.to_be(), port.to_be());
        let connection = KConnection {
            from: endpoint,
            to: endpoint,
        };

        let packet = Packet {
            flag: PacketFlag::ACK | PacketFlag::SYN,
            ack_seq: 128,
            seq: 129,
        };

        let notification = Notification {
            local_in_endpoint: endpoint,
            lcoal_out_endpoint: endpoint,
            connection,
            event: Event::TcpPacket(packet),
        };

        let p = &notification as *const Notification;

        const SIZE: usize = core::mem::size_of::<Notification>();

        let mut buffer = [0; SIZE];
        unsafe {
            core::ptr::copy_nonoverlapping(p as *const u8, buffer.as_mut_ptr(), SIZE);
        }

        let bs: &[u8] = &buffer[..];

        let got_notification = Notification::from_bytes(bs);

        assert_eq!(notification, got_notification);
    }
}
