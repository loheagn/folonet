#![no_std]

use network_types::{ip::IpProto, tcp::TcpHdr, udp::UdpHdr};

pub struct Address {
    pub proto: IpProto,
    pub ip: u32,
    pub port: u16,
}

pub struct LinkPair {
    pub local_mac: [u8; 6],
    pub remote_mac: [u8; 6],
    pub iface: [u8; 16],
}

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
}

pub struct Way {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
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
