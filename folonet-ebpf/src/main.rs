#![no_std]
#![no_main]
#![feature(offset_of)]

use aya_bpf::{
    bindings::xdp_action,
    helpers::bpf_csum_diff,
    macros::{map, xdp},
    maps::{HashMap, RingBuf},
    programs::XdpContext,
};

use aya_log_ebpf::debug;
use core::{
    mem::{self, offset_of},
    ptr::copy,
};
use folonet_common::{csum_fold_helper, BiPort, KConnection, KEndpoint, L4Hdr, Mac, LOCAL_IP};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[xdp]
pub fn folonet(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start_addr = ctx.data();

    if start_addr + offset + mem::size_of::<T>() > ctx.data_end() {
        return Err(());
    }

    Ok((start_addr + offset) as *mut T)
}

#[map]
static CONNECTION: HashMap<KConnection, KConnection> = HashMap::with_max_entries(1024, 0);

#[map]
static SERVER_MAP: HashMap<KEndpoint, KEndpoint> = HashMap::with_max_entries(1024, 0);

#[map]
static SERVER_PORT_MAP: HashMap<KEndpoint, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static IP_MAC_MAP: HashMap<u32, Mac> = HashMap::with_max_entries(1024, 0);

#[map]
static PACKET_EVENT: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[inline(always)]
fn extract_way(iphdr: *const Ipv4Hdr, l4_hdr: &L4Hdr) -> Result<KConnection, ()> {
    let src_ip = unsafe { (*iphdr).src_addr };
    let dst_ip = unsafe { (*iphdr).dst_addr };

    let src_port = l4_hdr.get_source();
    let dst_port = l4_hdr.get_dest();

    let connection = KConnection {
        from: KEndpoint::new(src_ip, src_port),
        to: KEndpoint::new(dst_ip, dst_port),
    };

    Ok(connection)
}

#[inline(always)]
fn update_csum(
    ctx: &XdpContext,
    iphdr: *mut Ipv4Hdr,
    l4_hdr: &mut L4Hdr,
    offset: usize,
    new_val: u32,
    update_ip_csum: bool,
) -> Result<(), ()> {
    let old_l4_csum = l4_hdr.get_check();
    let from_ptr: *mut u32 = ptr_at(&ctx, offset)?;
    let mut new_val = new_val;
    let to_ptr: *mut u32 = &mut new_val as *mut u32;
    let new_l4_csum = unsafe { bpf_csum_diff(from_ptr, 4, to_ptr, 4, !(old_l4_csum) as u32) };
    l4_hdr.set_check(csum_fold_helper(new_l4_csum as u64));

    if update_ip_csum {
        let old_ip_csum = unsafe { (*iphdr).check };
        let new_ip_csum = unsafe { bpf_csum_diff(from_ptr, 4, to_ptr, 4, !(old_ip_csum) as u32) };
        unsafe { (*iphdr).check = csum_fold_helper(new_ip_csum as u64) }
    }

    Ok(())
}

#[inline(always)]
fn update_packet_by_way(
    ctx: &XdpContext,
    ethhdr: *mut EthHdr,
    iphdr: *mut Ipv4Hdr,
    l4_hdr: &mut L4Hdr,
    way: &KConnection,
) -> Result<(), ()> {
    let dst = way.to;
    let src = way.from;

    // update dst ip
    update_csum(
        &ctx,
        iphdr,
        l4_hdr,
        EthHdr::LEN + offset_of!(Ipv4Hdr, dst_addr),
        dst.ip(),
        true,
    )?;
    unsafe {
        (*iphdr).dst_addr = dst.ip();
    };

    // udpate src ip
    update_csum(
        &ctx,
        iphdr,
        l4_hdr,
        EthHdr::LEN + offset_of!(Ipv4Hdr, src_addr),
        src.ip(),
        true,
    )?;
    unsafe {
        (*iphdr).src_addr = src.ip();
    }

    // update port
    let bi_port = BiPort::new(src.port(), dst.port());
    update_csum(
        ctx,
        iphdr,
        l4_hdr,
        EthHdr::LEN + Ipv4Hdr::LEN + offset_of!(TcpHdr, source),
        BiPort::new(src.port(), dst.port()).into(),
        false,
    )?;
    l4_hdr.set_bi_port(&bi_port);

    // set mac
    let src_mac: Mac = unsafe { (*ethhdr).src_addr }.into();
    let src_mac: [u8; 6] = src_mac.into();
    let src_mac_ptr: *mut [u8; 6] =
        ((ethhdr as usize) + offset_of!(EthHdr, src_addr)) as *mut [u8; 6];

    let dst_mac: [u8; 6] = if let Some(mac) = unsafe { IP_MAC_MAP.get(&dst.ip()) } {
        (*mac).into()
    } else {
        unsafe { *((ethhdr as usize + offset_of!(EthHdr, src_addr)) as *const [u8; 6]) }
    };
    let dst_mac_ptr: *mut [u8; 6] =
        ((ethhdr as usize) + offset_of!(EthHdr, dst_addr)) as *mut [u8; 6];

    unsafe {
        copy(&src_mac, src_mac_ptr, 6);
        copy(&dst_mac, dst_mac_ptr, 6);
    }

    Ok(())
}

#[inline(always)]
fn debug_connection(ctx: &XdpContext, way: &KConnection, extra_info: &str) -> Result<(), ()> {
    debug!(
        ctx,
        "{} from {:i}:{}, to {:i}:{}",
        extra_info,
        u32::from_be(way.from.ip()),
        u16::from_be(way.from.port()),
        u32::from_be(way.to.ip()),
        u16::from_be(way.to.port())
    );
    Ok(())
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *mut EthHdr = ptr_at(&ctx, 0)?;

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let iphdr: *mut Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;

    let proto: IpProto = unsafe { (*iphdr).proto };

    let mut l4_hdr: L4Hdr = match proto {
        IpProto::Tcp => {
            let tcphdr: *mut TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            L4Hdr::TcpHdr(tcphdr)
        }
        IpProto::Udp => {
            let udphdr: *mut UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            L4Hdr::UdpHdr(udphdr)
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    let declare_way = extract_way(iphdr, &l4_hdr)?;

    if let Some(mut e) = PACKET_EVENT.reserve::<u32>(0) {
        e.write(declare_way.from.ip());
        e.submit(0);
    }

    debug_connection(&ctx, &declare_way, "input: ")?;

    if unsafe { CONNECTION.get(&declare_way) }.is_none() {
        if unsafe { SERVER_PORT_MAP.get(&declare_way.to) }.is_none() {
            return Ok(xdp_action::XDP_PASS);
        }

        // create output way
        // find a available way
        let from = KEndpoint::new(LOCAL_IP.to_be(), 8899u16.to_be());
        let to = match unsafe { SERVER_MAP.get(&declare_way.to) } {
            Some(to) => to,
            None => return Ok(xdp_action::XDP_PASS),
        };
        let out_way = KConnection { from, to: *to };
        CONNECTION
            .insert(&declare_way, &out_way, 0)
            .map_err(|_| ())?;

        // and, we need to record the return way
        let return_output_way = out_way.reverse();
        let return_declare_way = &declare_way.reverse();
        CONNECTION
            .insert(&return_output_way, &return_declare_way, 0)
            .map_err(|_| ())?;
    }

    if let Some(output_way) = unsafe { CONNECTION.get(&declare_way) } {
        debug_connection(&ctx, &output_way, "output:")?;
        update_packet_by_way(&ctx, ethhdr, iphdr, &mut l4_hdr, &output_way)?;
        return Ok(xdp_action::XDP_TX);
    }

    Ok(xdp_action::XDP_PASS)
}
