#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_csum_diff,
    macros::{map, xdp},
    maps::{HashMap, Queue, RingBuf, Stack},
    programs::XdpContext,
};

use aya_log_ebpf::{debug, info, warn};
use core::{
    hash::Hash,
    mem::{self, offset_of},
    ptr::copy,
};
use folonet_common::{
    csum_fold_helper, event::Event, BiPort, KConnection, KEndpoint, L4Hdr, Mac, Notification,
    PORTS_QUEUE_SIZE,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

mod maps;

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
static IP_MAC_MAP: HashMap<u32, Mac> = HashMap::with_max_entries(1024, 0);

#[map]
static PACKET_EVENT: RingBuf = RingBuf::with_byte_size(256 * 1024 * 10, 0);

#[map]
static SERVICE_PORTS: Queue<u16> = Queue::with_max_entries(PORTS_QUEUE_SIZE, 0);

#[map]
static LOCAL_IP_MAP: HashMap<u32, u32> = HashMap::with_max_entries(10, 0);

#[map]
static COLD_START_MAP: RingBuf = RingBuf::with_byte_size(256 * 1024 * 10, 0);

#[map]
static DOOR_BELL_MAP: HashMap<KEndpoint, u8> = HashMap::with_max_entries(102400, 0);

#[map]
static PERFORMANCE_MAP: HashMap<KEndpoint, u8> = HashMap::with_max_entries(102400, 0);

#[inline(always)]
fn extract_way(
    ethhdr: *const EthHdr,
    iphdr: *const Ipv4Hdr,
    l4_hdr: &L4Hdr,
) -> Result<KConnection, ()> {
    let src_ip = unsafe { (*iphdr).src_addr };
    let dst_ip = unsafe { (*iphdr).dst_addr };

    let src_port = l4_hdr.get_source();
    let dst_port = l4_hdr.get_dest();

    let connection = KConnection {
        from: KEndpoint::new(src_ip, src_port),
        to: KEndpoint::new(dst_ip, dst_port),
    };

    // record ip with mac
    if unsafe { IP_MAC_MAP.get(&src_ip).is_none() } {
        unsafe {
            let mac = Mac::from((*ethhdr).src_addr);
            IP_MAC_MAP.insert(&src_ip, &mac, 0).map_err(|_| {})?;
        };
    }
    if unsafe { IP_MAC_MAP.get(&dst_ip).is_none() } {
        unsafe {
            let mac = Mac::from((*ethhdr).dst_addr);
            IP_MAC_MAP.insert(&dst_ip, &mac, 0).map_err(|_| {})?;
        };
    }

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

    // update src ip
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
    let src_mac: Mac = unsafe { (*ethhdr).dst_addr }.into();
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
    let xdp_md_ctx = unsafe { *(ctx.ctx) };
    let ifidx = xdp_md_ctx.ingress_ifindex;

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

    let declare_way = extract_way(ethhdr, iphdr, &l4_hdr)?;

    debug_connection(&ctx, &declare_way, "before check connection map").unwrap();

    if unsafe { CONNECTION.get(&declare_way) }.is_none() {
        // debug_connection(&ctx, &declare_way, "cannot find output way").unwrap();
        let to = match unsafe { SERVER_MAP.get(&declare_way.to) } {
            Some(to) => to,
            None => {
                let port = declare_way.to.port().to_be();
                if port < 8000 || port > 9999 {
                    // do not bother other ports
                    return Ok(xdp_action::XDP_PASS);
                }

                info!(
                    &ctx,
                    "need to cold start: {:i}:{}",
                    declare_way.to.ip().to_be(),
                    declare_way.to.port().to_be()
                );

                if let Some(mut e) = COLD_START_MAP.reserve::<KEndpoint>(0) {
                    let endpoint = declare_way.to.clone();
                    e.write(endpoint);
                    e.submit(0);
                }

                return Ok(xdp_action::XDP_DROP);
            }
        };
        let from_port = SERVICE_PORTS.pop();
        if from_port.is_none() {
            info!(
                &ctx,
                "from port is none: {:i}:{}",
                // SERVICE_PORTS.capacity(),
                declare_way.to.ip().to_be(),
                declare_way.to.port().to_be()
            );
            return Ok(xdp_action::XDP_DROP);
        }
        // debug_connection(&ctx, &declare_way, "get from port").unwrap();
        let from_port = from_port.unwrap();
        let local_ip = unsafe { LOCAL_IP_MAP.get(&ifidx) };
        if local_ip.is_none() {
            info!(
                &ctx,
                "local ip is none: {:i}:{}",
                declare_way.to.ip().to_be(),
                declare_way.to.port().to_be()
            );
            return Ok(xdp_action::XDP_DROP);
        }
        // debug_connection(&ctx, &declare_way, "get local ip").unwrap();
        let local_ip = local_ip.unwrap();
        let from = KEndpoint::new(local_ip.to_be(), from_port.to_be());

        // debug_connection(&ctx, &declare_way, "before insert connection map").unwrap();

        let out_way = KConnection { from, to: *to };
        CONNECTION
            .insert(&declare_way, &out_way, 0)
            .map_err(|_| ())?;

        // debug_connection(&ctx, &declare_way, "after insert connection map").unwrap();

        // and, we need to record the return way
        let return_output_way = out_way.reverse();
        let return_declare_way = &declare_way.reverse();
        CONNECTION
            .insert(&return_output_way, &return_declare_way, 0)
            .map_err(|_| ())?;
    }

    let output_way = unsafe { CONNECTION.get(&declare_way) };

    if output_way.is_none() {
        info!(
            &ctx,
            "output_way is none: {:i}:{}",
            declare_way.to.ip().to_be(),
            declare_way.to.port().to_be()
        );
        return Ok(xdp_action::XDP_PASS);
    }

    let output_way = output_way.unwrap();

    // debug_connection(&ctx, &output_way, "output:")?;

    // notify to userspace
    if l4_hdr.is_fin() {
        if let Some(mut e) = PACKET_EVENT.reserve::<Notification>(0) {
            let notification = Notification {
                local_in_endpoint: declare_way.to,
                lcoal_out_endpoint: output_way.from,
                connection: KConnection {
                    from: declare_way.from,
                    to: output_way.to,
                },
                event: Event::new_packet_event(&l4_hdr),
            };
            e.write(notification);
            e.submit(0);
            // info!(
            //     &ctx,
            //     "packet event is submit: {:i}:{}",
            //     declare_way.to.ip().to_be(),
            //     declare_way.to.port().to_be()
            // );
        } else {
            info!(
                &ctx,
                "packet event is full: {:i}:{}",
                declare_way.to.ip().to_be(),
                declare_way.to.port().to_be()
            );
        }
    }

    let target_endpoint = if let Some(v) = unsafe { DOOR_BELL_MAP.get(&declare_way.to) } {
        if *v == 1 {
            Some(&declare_way.to)
        } else {
            None
        }
    } else if let Some(v) = unsafe { DOOR_BELL_MAP.get(&output_way.from) } {
        if *v == 1 {
            Some(&output_way.from)
        } else {
            None
        }
    } else {
        None
    };

    if let Some(target_endpoint) = target_endpoint {
        let v = 1u8;
        // info!(
        //     &ctx,
        //     "record performace: {:i}:{}",
        //     target_endpoint.ip().to_be(),
        //     target_endpoint.port().to_be()
        // );
        PERFORMANCE_MAP.insert(&target_endpoint, &v, 0).unwrap();
    }

    update_packet_by_way(&ctx, ethhdr, iphdr, &mut l4_hdr, &output_way)?;

    Ok(xdp_action::XDP_TX)
}
