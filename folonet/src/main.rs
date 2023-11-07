use anyhow::{Context, Ok};
use aya::maps::{HashMap as AyaHashmap, MapData as AyaMapData, RingBuf};
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use folonet_common::{
    KEndpoint, Mac, Notification, CLIENT_IP, CLIENT_MAC, LOCAL_IP, SERVER_IP, SERVER_MAC,
};
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::runtime::Runtime;
use tokio::signal;

use crate::endpoint::{endpoint_pair_from_notification, Endpoint, UConnection, UEndpoint};
use crate::message::Message;
use crate::service::Service;
use crate::worker::MsgWorker;

mod endpoint;
mod message;
mod service;
mod state;
mod worker;

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
    let local_left_endpoint = UEndpoint::new(KEndpoint::new(LOCAL_IP.to_be(), 80u16.to_be()));
    let server_endpoint = UEndpoint::new(KEndpoint::new(SERVER_IP.to_be(), 80u16.to_be()));
    let mut server_map: AyaHashmap<_, UEndpoint, UEndpoint> =
        AyaHashmap::try_from(bpf.map_mut("SERVER_MAP").unwrap()).unwrap();
    server_map.insert(&local_left_endpoint, &server_endpoint, 0)?;

    let mut server_port: AyaHashmap<_, UEndpoint, u8> =
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

    let iface_list = ["ens33", "ens37", "lo"];
    iface_list.iter().for_each(|iface| {
        let opt = Opt {
            iface: iface.to_string(),
        };
        program.attach(&opt.iface, XdpFlags::default())
                .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE").unwrap();
    });

    let mut bpf_packet_event_map = bpf.take_map("PACKET_EVENT").unwrap();
    let bpf_connection_map = bpf.take_map("CONNECTION").unwrap();

    std::thread::spawn(move || {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let bpf_connection_map: AyaHashmap<AyaMapData, UConnection, UConnection> =
                AyaHashmap::try_from(bpf_connection_map).unwrap();
            let connection_map = Arc::new(tokio::sync::Mutex::new(bpf_connection_map));

            let mut tcp_service_map: HashMap<Endpoint, MsgWorker<Service>> = HashMap::new();
            let mut udp_service_map: HashMap<Endpoint, MsgWorker<Service>> = HashMap::new();

            // FIXME: fill the service maps
            let local_endpoint = Endpoint {
                ip: Ipv4Addr::from(LOCAL_IP),
                port: 80,
            };
            tcp_service_map.insert(
                local_endpoint.clone(),
                MsgWorker::new(Service::new(
                    "test".to_string(),
                    local_endpoint,
                    vec![Endpoint {
                        ip: Ipv4Addr::from(SERVER_IP),
                        port: 80,
                    }],
                    true,
                    connection_map.clone(),
                )),
            );

            let mut ring_buf: RingBuf<&mut aya::maps::MapData> =
                RingBuf::try_from(&mut bpf_packet_event_map).unwrap();
            let fd = AsyncFd::new(ring_buf.as_raw_fd()).unwrap();
            loop {
                let _ = fd.readable().await.unwrap();

                if let Some(item) = ring_buf.next() {
                    let notification = Notification::from_bytes(item.deref());
                    let (from_endpoint, to_endpoint) =
                        endpoint_pair_from_notification(&notification);
                    let local_in_endpoint = Endpoint::new(notification.local_in_endpoint);
                    let local_out_endpoint = Endpoint::new(notification.lcoal_out_endpoint);

                    info!(
                        "from {} to {}",
                        from_endpoint.to_string(),
                        to_endpoint.to_string()
                    );

                    info!(
                        "local_in_endpoint {} lcoal_out_endpoint {}",
                        local_in_endpoint.to_string(),
                        local_out_endpoint.to_string(),
                    );

                    let service = if notification.is_tcp() {
                        tcp_service_map
                            .get(&local_in_endpoint)
                            .or_else(|| tcp_service_map.get(&local_out_endpoint))
                    } else {
                        udp_service_map
                            .get(&local_in_endpoint)
                            .or_else(|| udp_service_map.get(&local_out_endpoint))
                    };

                    if let Some(service) = service {
                        if let Some(sender) = service.msg_sender() {
                            let msg = Message::from_notification(notification);
                            let result = sender.send(msg.clone()).await;
                            if result.is_err() {
                                error!(
                                    "failed to send message {:?}, error detail: {:?}",
                                    msg,
                                    result.err().unwrap(),
                                );
                            }
                        }
                    }
                }
            }
        });
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

mod test {

    #[test]
    fn map_test() {
        use std::collections::HashMap;
        let mut map: HashMap<i32, i32> = HashMap::new();

        map.insert(4, 5);

        let v = map.get(&3).or_else(|| map.get(&4)).unwrap();

        assert_eq!(*v, 5);
    }
}
