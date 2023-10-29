#![no_std]

use byteorder::{BigEndian, ByteOrder};
use network_types::{tcp::TcpHdr, udp::UdpHdr};

pub const CLIENT_IP: u32 = 3232262401;
pub const SERVER_IP: u32 = 3232262406;
pub const LOCAL_IP: u32 = 3232262404;

pub const SERVER_MAC: [u8; 6] = [82, 85, 85, 61, 116, 111];
pub const LOCAL_MAC: [u8; 6] = [82, 85, 85, 93, 65, 176];
pub const CLIENT_MAC: [u8; 6] = [0x5e, 0x52, 0x30, 0xa9, 0xb5, 0x64];

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

#[derive(Debug, Clone, Copy, Default)]
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

#[derive(Debug, Clone, Copy, Default)]
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

mod test {

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
        use crate::LOCAL_IP;

        let ip = LOCAL_IP;
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
}
