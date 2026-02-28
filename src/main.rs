use dotenvy::dotenv;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use std::{env, time};
use tokio::net::UdpSocket;
use tokio::{io::AsyncWriteExt, net::TcpListener};

lazy_static::lazy_static! {
    pub static ref PORT: Vec<u16> = {
        dotenv().ok();
        env::var("PORT")
            .unwrap_or_else(|_| "25565".into())
            .split(',')
            .filter_map(|s| s.trim().parse::<u16>().ok())
            .collect::<Vec<u16>>()
    };
    pub static ref UPORT: Vec<u16> = {
        dotenv().ok();
        env::var("UPORT")
            .unwrap_or_else(|_| "19132".into())
            .split(',')
            .filter_map(|s| s.trim().parse::<u16>().ok())
            .collect::<Vec<u16>>()
    };
    pub static ref HOST: String = {
        dotenv().ok();
        env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into())
    };
    pub static ref DEVICE: String = {
        dotenv().ok();
        env::var("DEVICE").unwrap_or_else(|_| "any".into())
    };
}

type DedupMap = Arc<Mutex<HashMap<std::net::IpAddr, Instant>>>;
const DEDUP_WINDOW: Duration = Duration::from_secs(1800);

#[tokio::main]
async fn main() {
    println!("Starting Minecraft Banbot...");
    println!(
        "{}{}",
        console::style("action log for fail2ban or similar like this: ").red(),
        console::style("tcp/25565 abuse detected for ip=the_ip_here").magenta()
    );
    let (tx, rx) = std::sync::mpsc::channel::<(SocketAddr, u16, &'static str, &'static str)>();
    let seen_scans = Arc::new(Mutex::new(HashSet::new()));
    let dedup_map: DedupMap = Arc::new(Mutex::new(HashMap::new()));

    // --- Spawn a thread for each UDP port ---
    for uport in UPORT.iter().copied() {
        let tx_udp = tx.clone();
        let host = HOST.clone();
        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                let socket = UdpSocket::bind(format!("{}:{}", host, uport))
                    .await
                    .unwrap_or_else(|e| {
                        eprintln!("Failed to bind UDP socket to port {:#?}: {e}", uport);
                        std::process::exit(1);
                    });
                println!("Listening on UDP {}:{}", host, uport);
                let mut buf = [0u8; 2048];
                loop {
                    match socket.recv_from(&mut buf).await {
                        Ok((_, addr)) => {
                            let _ = tx_udp.send((addr, uport, "full_conn", "udp"));
                        }
                        Err(e) => eprintln!("UDP recv error: {e}"),
                    }
                }
            });
        });
    }

    // --- Spawn a thread for each TCP port ---
    for port in PORT.iter().copied() {
        let tx_tcp = tx.clone();
        let host = HOST.clone();
        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                let listener = TcpListener::bind(format!("{}:{}", host, port))
                    .await
                    .unwrap_or_else(|e| {
                        eprintln!("Failed to bind to port {:#?}: {e}", port);
                        std::process::exit(1);
                    });
                println!("Listening on {}:{}", host, port);
                loop {
                    match listener.accept().await {
                        Ok((mut socket, addr)) => {
                            let tx = tx_tcp.clone();
                            tokio::spawn(async move {
                                let _ = tx.send((addr, port, "full_conn", "tcp"));
                                tokio::time::sleep(time::Duration::from_secs(1)).await;
                                let _ = socket.shutdown().await;
                            });
                        }
                        Err(e) => eprintln!("Accept error: {e}"),
                    }
                }
            });
        });
    }

    // Spawn the packet sniffer in a thread for each device
    let tx_sniffer = tx.clone();
    thread::spawn(move || {
        use etherparse::{InternetSlice, SlicedPacket};
        use pcap::{Capture, Device};

        // This code gets all devices to sniff for packets
        let mut devices = match Device::list() {
            Ok(devs) => devs,
            Err(e) => {
                eprintln!("Failed to list devices: {e}");
                return;
            }
        };

        match DEVICE.as_str() {
            "any" => {
                println!("{}", DEVICE.as_str());
                println!("Sniffing on all devices:");
                for dev in &devices {
                    println!("  {}", dev.name);
                }
            } // Use all devices
            dev_name => {
                // Filter to only the specified device
                if let Some(dev) = devices.iter().find(|d| d.name == dev_name) {
                    println!("Sniffing on device: {}", dev.name);
                    devices = vec![dev.clone()];
                } else {
                    eprintln!("Device '{}' not found. Available devices:", dev_name);
                    for dev in &devices {
                        eprintln!("  {}", dev.name);
                    }
                    return;
                }
            }
        }

        // For each device, spawn a sniffer thread
        for dev in devices {
            let tx_sniffer = tx_sniffer.clone();
            let dev_name = dev.name.clone();
            let seen_scans = seen_scans.clone();
            thread::spawn(move || {
                // Open a packet capture on the device and filter for TCP port 25565
                let mut cap = match Capture::from_device(dev_name.as_str())
                    .map(|c| c.promisc(true).immediate_mode(true))
                    .and_then(|c| c.open())
                {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Failed to open capture on {}: {e}", dev_name);
                        return;
                    }
                };
                if let Err(e) = cap.filter("tcp dst port 25565 or udp dst port 19132", true) {
                    eprintln!("Failed to set filter on {}: {e}", dev_name);
                    return;
                }

                // Main packet processing loop for this device
                while let Ok(packet) = cap.next_packet() {
                    if let Ok(ref pkt) = SlicedPacket::from_ethernet(packet.data) {
                        if let Some(ref tcp) = pkt.transport
                            && let etherparse::TransportSlice::Tcp(tcp) = tcp
                        {
                            // Check for SYN and not ACK (SYN scan)
                            if tcp.syn()
                                && !tcp.ack()
                                && tcp.destination_port() == 25565
                                && let Some(ref net) = pkt.net
                            {
                                let src = match net {
                                    InternetSlice::Ipv4(h) => {
                                        let hdr = h.header();
                                        let ip = std::net::Ipv4Addr::from(hdr.source());
                                        SocketAddr::new(std::net::IpAddr::V4(ip), tcp.source_port())
                                    }
                                    InternetSlice::Ipv6(h) => {
                                        let hdr = h.header();
                                        let ip = std::net::Ipv6Addr::from(hdr.source());
                                        SocketAddr::new(std::net::IpAddr::V6(ip), tcp.source_port())
                                    }
                                    InternetSlice::Arp(_) => return,
                                };
                                // Deduplicate SYN scans per (IP, port)
                                let mut seen = seen_scans.lock().unwrap_or_else(|e| {
                                    eprintln!("Failed to lock seen_scans: {e}");
                                    std::process::exit(1);
                                });
                                let key = (src.ip(), src.port());
                                if !seen.contains(&key) {
                                    seen.insert(key);
                                    let _ = tx_sniffer.send((
                                        src,
                                        tcp.destination_port(),
                                        "syn_scan",
                                        "tcp",
                                    ));
                                }
                            }
                        }
                        if let Some(ref udp) = pkt.transport
                            && let etherparse::TransportSlice::Udp(udp) = udp
                            && udp.destination_port() == 19132
                            && let Some(ref net) = pkt.net
                        {
                            let src = match net {
                                InternetSlice::Ipv4(h) => {
                                    let hdr = h.header();
                                    let ip = std::net::Ipv4Addr::from(hdr.source());
                                    SocketAddr::new(std::net::IpAddr::V4(ip), udp.source_port())
                                }
                                InternetSlice::Ipv6(h) => {
                                    let hdr = h.header();
                                    let ip = std::net::Ipv6Addr::from(hdr.source());
                                    SocketAddr::new(std::net::IpAddr::V6(ip), udp.source_port())
                                }
                                InternetSlice::Arp(_) => return,
                            };

                            // Parse the UDP payload to distinguish packet types
                            if let Some(_payload) = pkt.ip_payload() {
                                // You can add your Bedrock protocol detection here
                                // For now, just send every UDP packet to process
                                let _ = tx_sniffer.send((
                                    src,
                                    udp.destination_port(),
                                    "bedrock_udp",
                                    "udp",
                                ));
                            }
                        }
                    }
                }
            });
        }
    }); // <-- closes the thread::spawn for the sniffer

    // --- Main event loop: process incoming IPs from both TCP and sniffer threads ---
    for (addr, server_port, kind, proto) in rx {
        let dedup_map = dedup_map.clone();
        if let Err(e) =
            badip_check_abipdb::process(addr, server_port, kind, proto, dedup_map, DEDUP_WINDOW)
                .await
        {
            eprintln!("Error in process(): {e}");
        }
    }
}
