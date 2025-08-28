use dotenvy::dotenv;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use std::{env, time};
use tokio::net::UdpSocket;
use tokio::{io::AsyncWriteExt, net::TcpListener};

lazy_static::lazy_static! {
    pub static ref API_KEY: String = {
        dotenv().ok();
        env::var("API_KEY").expect("API_KEY must be set in .env or environment")
    };
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
const DEDUP_WINDOW: Duration = Duration::from_secs(30);

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
                    .and_then(|c| Ok(c.promisc(true).immediate_mode(true)))
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
                    if let Ok(ref pkt) = SlicedPacket::from_ethernet(&packet.data) {
                        if let Some(ref tcp) = pkt.transport {
                            if let etherparse::TransportSlice::Tcp(tcp) = tcp {
                                // Check for SYN and not ACK (SYN scan)
                                if tcp.syn() && !tcp.ack() && tcp.destination_port() == 25565 {
                                    if let Some(ref net) = pkt.net {
                                        let src = match net {
                                            InternetSlice::Ipv4(h) => {
                                                let hdr = h.header();
                                                let ip = std::net::Ipv4Addr::from(hdr.source());
                                                SocketAddr::new(
                                                    std::net::IpAddr::V4(ip),
                                                    tcp.source_port(),
                                                )
                                            }
                                            InternetSlice::Ipv6(h) => {
                                                let hdr = h.header();
                                                let ip = std::net::Ipv6Addr::from(hdr.source());
                                                SocketAddr::new(
                                                    std::net::IpAddr::V6(ip),
                                                    tcp.source_port(),
                                                )
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
                            }
                        }
                        if let Some(ref udp) = pkt.transport {
                            if let etherparse::TransportSlice::Udp(udp) = udp {
                                if udp.destination_port() == 19132 {
                                    if let Some(ref net) = pkt.net {
                                        let src = match net {
                                            InternetSlice::Ipv4(h) => {
                                                let hdr = h.header();
                                                let ip = std::net::Ipv4Addr::from(hdr.source());
                                                SocketAddr::new(
                                                    std::net::IpAddr::V4(ip),
                                                    udp.source_port(),
                                                )
                                            }
                                            InternetSlice::Ipv6(h) => {
                                                let hdr = h.header();
                                                let ip = std::net::Ipv6Addr::from(hdr.source());
                                                SocketAddr::new(
                                                    std::net::IpAddr::V6(ip),
                                                    udp.source_port(),
                                                )
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
                        }
                    }
                }
            });
        }
    }); // <-- closes the thread::spawn for the sniffer

    // --- Main event loop: process incoming IPs from both TCP and sniffer threads ---
    for (addr, server_port, kind, proto) in rx {
        let dedup_map = dedup_map.clone();
        if let Err(e) = process(addr, server_port, kind, proto, dedup_map).await {
            eprintln!("Error in process(): {e}");
        }
    }
} // <-- closes async fn main

// --- Process function: handles abuse checks and deduplication for each event ---
async fn process(
    addr: SocketAddr,
    server_port: u16,
    kind: &str,
    proto: &str,
    dedup_map: DedupMap,
) -> Result<(), Box<dyn std::error::Error>> {
    // Always log the event, even if deduplicated
    match kind {
        "full_conn" => println!("Processing FULL connection from: {addr}"),
        "syn_scan" => println!("Detected SYN scan from: {addr}"),
        "bedrock_udp" => println!("Detected Minecraft Bedrock UDP packet from: {addr}"),
        _ => println!("Unknown event from: {addr}"),
    }

    let ip = addr.ip();
    let is_private = match ip {
        std::net::IpAddr::V4(ipv4) => ipv4.is_private(),
        std::net::IpAddr::V6(ipv6) => {
            // Unique local addresses (fc00::/7) are considered private in IPv6
            ipv6.segments()[0] & 0xfe00 == 0xfc00
        }
    };

    // Ignore local, multicast, or private IPs
    if ip.is_loopback() || ip.is_multicast() || is_private {
        println!("Ignoring private, loopback or multicast IP: {}", ip);
        return Ok(());
    }

    // Only deduplicate API requests, not logs
    let mut do_lookup = true;
    {
        let mut map = dedup_map.lock().unwrap_or_else(|e| {
            eprintln!("Failed to lock dedup_map: {e}");
            std::process::exit(1);
        });
        let now = Instant::now();
        if let Some(&last) = map.get(&ip) {
            if now.duration_since(last) < DEDUP_WINDOW {
                println!("Skipping API request for {} (deduplicated)", ip);
                do_lookup = false;
            }
        }
        if do_lookup {
            map.insert(ip, now);
        }
    }

    if !do_lookup {
        return Ok(());
    }

    // --- AbuseIPDB API request and response handling ---
    let client = Client::new();

    let res = client
        .get("https://api.abuseipdb.com/api/v2/check")
        .query(&[
            ("ipAddress", ip.to_string()),
            ("maxAgeInDays", "90".to_string()),
        ])
        .header("Accept", "application/json")
        .header("Key", API_KEY.to_string())
        .send()
        .await?
        .json::<AbuseIpDbResponse>()
        .await?;

    let data = res.data;

    // --- Abuse detection logic and logging ---
    let high_abuse = data.abuse_confidence_score.unwrap_or(0) > 50;
    let many_reports =
        data.total_reports.unwrap_or(0) > 5 && data.num_distinct_users.unwrap_or(0) > 3;

    if high_abuse {
        println!("High abuse confidence score detected for IP: {}", ip);
    }
    if many_reports {
        println!("Multiple abuse reports detected for IP: {}", ip);
    }
    if high_abuse || many_reports {
        println!(
            "{}",
            console::style(format!(
                "{}/{} abuse detected for ip={}",
                proto, server_port, ip
            ))
            .magenta()
        );
    }

    Ok(())
}

// --- Serde structs for AbuseIPDB API response, with catch-all for extra fields ---

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AbuseIpDbResponse {
    pub data: AbuseIpDbData,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AbuseIpDbData {
    pub abuse_confidence_score: Option<u32>,
    pub country_code: Option<String>,
    pub domain: Option<String>,
    pub hostnames: Option<Vec<String>>,
    pub ip_address: Option<String>,
    pub ip_version: Option<u8>,
    pub is_public: Option<bool>,
    pub is_tor: Option<bool>,
    pub is_whitelisted: Option<Value>,
    pub isp: Option<String>,
    pub last_reported_at: Option<Value>,
    pub num_distinct_users: Option<u32>,
    pub total_reports: Option<u32>,
    pub usage_type: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}
