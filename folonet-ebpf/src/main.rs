#![no_std]
#![no_main]
#![feature(offset_of)]

use aya_bpf::{bindings::xdp_action, helpers::bpf_csum_diff, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use core::mem::{self, offset_of};
use folonet_common::{csum_fold_helper, L4Hdr, Way};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
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

fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start_addr = ctx.data();

    if start_addr + offset + mem::size_of::<T>() > ctx.data_end() {
        return Err(());
    }

    Ok((start_addr + offset) as *mut T)
}

const CLIENT_IP: u32 = 3232262401;
const SERVER_IP: u32 = 3232262406;
const LOCAL_IP: u32 = 3232262404;

const SERVER_MAC: [u8; 6] = [82, 85, 85, 61, 116, 111];
const LOCAL_MAC: [u8; 6] = [82, 85, 85, 93, 65, 176];
const CLIENT_MAC: [u8; 6] = [0x5e, 0x52, 0x30, 0xa9, 0xb5, 0x64];

#[inline(always)]
fn set_mac(ctx: &XdpContext, src_mac: &[u8; 6], dst_mac: &[u8; 6]) -> Result<(), ()> {
    let src_mac_ptr: *mut [u8; 6] = ptr_at(&ctx, offset_of!(EthHdr, src_addr))?;
    src_mac.iter().enumerate().for_each(|(i, &b)| unsafe {
        *((src_mac_ptr as usize + i) as *mut u8) = b;
    });

    let dst_mac_ptr: *mut [u8; 6] = ptr_at(&ctx, offset_of!(EthHdr, dst_addr))?;
    dst_mac.iter().enumerate().for_each(|(i, &b)| unsafe {
        *((dst_mac_ptr as usize + i) as *mut u8) = b;
    });

    Ok(())
}

#[inline(always)]
fn replace_update_csum<T>(ctx: &XdpContext, offset: usize, new_val: u32) -> Result<(), ()>
where
    *mut T: Into<L4Hdr>,
{
    let l4_hdr: *mut T = ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let l4_hdr: L4Hdr = l4_hdr.into();
    let old_l4_csum = l4_hdr.get_check();
    let from_ptr: *mut u32 = ptr_at(&ctx, offset)?;
    let mut new_val: u32 = new_val.to_be();
    let to_ptr: *mut u32 = &mut new_val as *mut u32;
    let new_l4_csum = unsafe { bpf_csum_diff(from_ptr, 4, to_ptr, 4, !(old_l4_csum) as u32) };
    l4_hdr.set_check(csum_fold_helper(new_l4_csum as u64));

    let iphdr: *mut Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    let old_ip_csum = unsafe { (*iphdr).check };
    let new_ip_csum = unsafe { bpf_csum_diff(from_ptr, 4, to_ptr, 4, !(old_ip_csum) as u32) };
    unsafe { (*iphdr).check = csum_fold_helper(new_ip_csum as u64) }

    Ok(())
}

#[inline(always)]
fn update_packet_by_way(ctx: &XdpContext, way: &Way) -> Result<(), ()> {
    let ipv4hdr: *mut Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;

    // update dst ip
    replace_update_csum::<TcpHdr>(
        &ctx,
        EthHdr::LEN + offset_of!(Ipv4Hdr, dst_addr),
        way.dst_ip,
    )?;
    unsafe {
        (*ipv4hdr).dst_addr = way.dst_ip.to_be();
    };

    // udpate src ip
    replace_update_csum::<TcpHdr>(
        &ctx,
        EthHdr::LEN + offset_of!(Ipv4Hdr, src_addr),
        way.src_ip,
    )?;
    unsafe {
        (*ipv4hdr).src_addr = way.src_ip.to_be();
    }

    set_mac(&ctx, &way.src_mac, &way.dst_mac)?;

    Ok(())
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *mut EthHdr = ptr_at(&ctx, 0)?;

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *mut Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;

    let proto: IpProto = unsafe { (*ipv4hdr).proto };

    if proto != IpProto::Tcp {
        return Ok(xdp_action::XDP_PASS);
    }

    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });

    info!(&ctx, "catch source ip: {:i}", source_addr);

    let way = match source_addr {
        SERVER_IP => Way {
            src_ip: LOCAL_IP,
            dst_ip: CLIENT_IP,
            src_mac: LOCAL_MAC,
            dst_mac: CLIENT_MAC,
        },
        CLIENT_IP => Way {
            src_ip: LOCAL_IP,
            dst_ip: SERVER_IP,
            src_mac: LOCAL_MAC,
            dst_mac: SERVER_MAC,
        },
        _ => return Ok(xdp_action::XDP_PASS),
    };

    info!(&ctx, "deal with source ip: {:i}", source_addr);

    update_packet_by_way(&ctx, &way)?;

    Ok(xdp_action::XDP_TX)
}
