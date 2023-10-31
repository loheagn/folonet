use anyhow::{Context, Ok};
use aya::maps::{HashMap as AyaHashmap, RingBuf};
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use byteorder::{BigEndian, ReadBytesExt};
use clap::Parser;
use folonet_common::{
    KEndpoint, Mac, Notification, CLIENT_IP, CLIENT_MAC, LOCAL_IP, SERVER_IP, SERVER_MAC,
};
use log::{debug, info, warn};
use std::net::Ipv4Addr;
use std::ops::Deref;
use std::os::fd::AsRawFd;
use tokio::io::unix::AsyncFd;
use tokio::runtime::Runtime;
use tokio::signal;

use crate::endpoint::Endpoint;

mod endpoint;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lima0")]
    iface: String,
}

fn get_bpf() -> Bpf {
    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/folonet"
    ))
    .unwrap();
    #[cfg(not(debug_assertions))]
    let bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/folonet"
    ))
    .unwrap();
    bpf
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let mut bpf = get_bpf();

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // init maps
    let local_left_endpoint = Endpoint::new(KEndpoint::new(LOCAL_IP.to_be(), 80u16.to_be()));
    let server_endpoint = Endpoint::new(KEndpoint::new(SERVER_IP.to_be(), 80u16.to_be()));
    let mut server_map: AyaHashmap<_, Endpoint, Endpoint> =
        AyaHashmap::try_from(bpf.map_mut("SERVER_MAP").unwrap()).unwrap();
    server_map.insert(&local_left_endpoint, &server_endpoint, 0)?;

    let mut server_port: AyaHashmap<_, Endpoint, u8> =
        AyaHashmap::try_from(bpf.map_mut("SERVER_PORT_MAP").unwrap())?;
    server_port.insert(&local_left_endpoint, 1, 0)?;

    let mut ip_mac_map: AyaHashmap<_, u32, u64> =
        AyaHashmap::try_from(bpf.map_mut("IP_MAC_MAP").unwrap()).unwrap();
    let server_mac: Mac = SERVER_MAC.into();
    ip_mac_map.insert(&SERVER_IP.to_be(), &(server_mac.val()), 0)?;
    let client_mac: Mac = CLIENT_MAC.into();
    ip_mac_map.insert(&CLIENT_IP.to_be(), &(client_mac.val()), 0)?;

    let program: &mut Xdp = bpf.program_mut("folonet").unwrap().try_into().unwrap();
    program.load().unwrap();

    let iface_list = ["lima0", "lima1"];
    iface_list.iter().for_each(|iface| {
        let opt = Opt {
            iface: iface.to_string(),
        };
        program.attach(&opt.iface, XdpFlags::default())
                .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE").unwrap();
    });

    std::thread::spawn(move || {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let mut ring_buf: RingBuf<&mut aya::maps::MapData> =
                RingBuf::try_from(bpf.map_mut("PACKET_EVENT").unwrap()).unwrap();
            let fd = AsyncFd::new(ring_buf.as_raw_fd()).unwrap();
            loop {
                let _ = fd.readable().await.unwrap();

                if let Some(item) = ring_buf.next() {
                    let data = item.deref();
                    let a = Notification::from_bytes(data);
                    let ip: Ipv4Addr = u32::from_be(a.connection.from.ip()).into();
                    info!("data: {}", ip.to_string());
                }
            }
        });
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
