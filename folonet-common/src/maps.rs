// use aya_bpf::{
//     bindings::xdp_action,
//     helpers::bpf_csum_diff,
//     macros::{map, xdp},
//     maps::{HashMap, Queue, RingBuf},
//     programs::XdpContext,
// };

// #[map]
// static SERVICE_PP: Queue<u16> = Queue::with_max_entries(50000, 0);
// static list: [&Queue<u16>; 1] = [&SERVICE_PP];
