#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;

use core::mem;
use aya_ebpf::bindings::BPF_F_NO_PREALLOC;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
struct Flow {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
}

#[map] //
static FLOWS: HashMap<Flow, u8> = HashMap::<Flow, u8>::with_max_entries(1024, BPF_F_NO_PREALLOC);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[xdp]
pub fn aya_app(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)] //
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let eth_hdr: *const EthHdr = ptr_at(&ctx, 0)?; //
    let mut flow = Flow::default();
    match unsafe { (*eth_hdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    flow.src_ip = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    flow.dst_ip = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    flow.protocol = unsafe { (*ipv4hdr).proto } as u8;

    let ipv4_len: usize = (unsafe { (*ipv4hdr).ihl() } << 2).into();
    (flow.src_port, flow.dst_port) = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcp_hdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + ipv4_len)?;
            (
                u16::from_be(unsafe { (*tcp_hdr).source }),
                u16::from_be(unsafe { (*tcp_hdr).dest }),
            )
        }
        IpProto::Udp => {
            let udp_hdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + ipv4_len)?;
            (
                u16::from_be(unsafe { (*udp_hdr).source }),
                u16::from_be(unsafe { (*udp_hdr).dest }),
            )
        }
        _ => return Err(()),
    };

    //if is_new_flow(&flow) {
    if unsafe { FLOWS.get(&flow) }.is_none(){
        info!(
            &ctx,
            "NEW FLOW: SRC IP: {:i}, DST IP: {:i}, SRC PORT: {}, DST PORT: {}, protocol:{} ",
            flow.src_ip,
            flow.dst_ip,
            flow.src_port,
            flow.dst_port,
            flow.protocol
        );
        FLOWS
            .insert(&flow, &1, 0)
            .expect("failed to insert flow into map");
    } else {
        info!(&ctx, "Flow already detcted SRC IP: {:i}, DST IP: {:i}, SRC PORT: {}, DST PORT: {}, protocol:{} ",
            flow.src_ip,
            flow.dst_ip,
            flow.src_port,
            flow.dst_port,
            flow.protocol)
    }

    Ok(xdp_action::XDP_PASS)
}
