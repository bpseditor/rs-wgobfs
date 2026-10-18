use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::rc::Rc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

#[cfg(test)]
mod chacha;
mod chacha_glue;
#[cfg(test)]
mod guts;
mod wgobfs;

use crate::wgobfs::MAX_RND_LEN;
use crate::wgobfs::{obfs_udp_payload, unobfs_udp_payload, ForwardState};

const HELP: &str = "\
USAGE:
  rs-wgobfs [OPTIONS]

OPTIONS:
  -h, --help                          Print help information
  -l or --listen <IP:Port>            Listen address:port
  -f or --forward <IP|Hostname:Port>  Peer's address:port
  -6                                  (Optional) Prefer IPv6 when connecting
                                      to the forward Peer

  -k or --key                         Shared secret (will be repeated or
                                      truncated to 32 characters)

  -m or --mode <obfs|unobfs>          Mode, either obfs or unobfs
";

#[derive(Copy, Clone)]
enum OPMode {
    Obfs,
    UnObfs,
}

struct AppArgs {
    local_addr: SocketAddr,
    fwd_addr: SocketAddr,
    key: [u8; 32],
    obfs_mode: OPMode,
}

fn parse_socket_addr(s: &str, prefer_v6: bool) -> Option<SocketAddr> {
    // without DNS
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Some(addr);
    }

    // use DNS
    let mut v4: Option<SocketAddr> = None;
    let mut v6: Option<SocketAddr> = None;
    let addrs = s.to_socket_addrs().ok()?;
    for addr in addrs {
        match addr {
            SocketAddr::V4(_) if v4.is_none() => v4 = Some(addr),
            SocketAddr::V6(_) if v6.is_none() => v6 = Some(addr),
            _ => {}
        }
    }

    if prefer_v6 {
        v6.or(v4)
    } else {
        v4.or(v6)
    }
}

fn create_dual_stack_socket(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    // create a raw socket2 Socket
    let socket: Socket;
    if addr.is_ipv4() {
        socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    } else {
        socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        // disable "IPv6 Only" to allow IPv4 traffic on the same socket
        socket.set_only_v6(false)?;
    }

    // Increase socket buffer to 1MB
    // Default sizes in Windows/Linux/BSDs are not big enough on Gigabit
    // network. There are many retries when testing the tunnel with iperf3.
    //
    // OpenBSD 7.8 defaults:
    //   net.inet.udp.recvspace=41600
    //   net.inet.udp.sendspace=9216
    socket.set_recv_buffer_size(1024 * 1024)?;
    socket.set_send_buffer_size(1024 * 1024)?;

    socket.bind(&addr.into())?;
    // convert to Tokio UdpSocket
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

fn expand_key(s: &str) -> Result<[u8; 32], pico_args::Error> {
    if s.is_empty() {
        return Err(pico_args::Error::ArgumentParsingFailed {
            cause: "key must not be empty".into(),
        });
    }
    let mut key = [0; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = s.as_bytes()[i % s.len()];
    }
    Ok(key)
}

fn parse_args() -> Result<AppArgs, pico_args::Error> {
    let mut pargs = pico_args::Arguments::from_env();

    if pargs.contains(["-h", "--help"]) {
        print!("{}", HELP);
        std::process::exit(0);
    }

    let local_str: String = pargs
        .value_from_str("--listen")
        .or_else(|_| pargs.value_from_str("-l"))?;
    let remote_str: String = pargs
        .value_from_str("--forward")
        .or_else(|_| pargs.value_from_str("-f"))?;

    let mode: String = pargs
        .value_from_str("--mode")
        .or_else(|_| pargs.value_from_str("-m"))?;

    let key: String = pargs
        .value_from_str("--key")
        .or_else(|_| pargs.value_from_str("-k"))?;

    let key_arr = expand_key(&key)?;

    let prefer_v6: bool = pargs.contains("-6");
    let args = AppArgs {
        local_addr: parse_socket_addr(&local_str, false)
            .expect("Failed to parse listening address"),
        fwd_addr: parse_socket_addr(&remote_str, prefer_v6)
            .expect("Failed to parse the remote address"),
        key: key_arr,
        obfs_mode: match mode.as_str() {
            "obfs" => OPMode::Obfs,
            "unobfs" => OPMode::UnObfs,
            _ => {
                eprintln!("Invalide --mode: {}", mode);
                std::process::exit(1);
            }
        },
    };

    Ok(args)
}

// Large enough for a non-jumbogram UDP payload, plus obfuscation padding.
const MAX_UDP_PAYLOAD: usize = 65_527;
const PACKET_BUFFER_SIZE: usize = MAX_UDP_PAYLOAD + MAX_RND_LEN;
const RECEIVE_BATCH: usize = 64;
const CLIENT_TIMEOUT: Duration = Duration::from_secs(600);
const SEND_TIMEOUT: Duration = Duration::from_millis(1);

#[derive(Default)]
struct SendErrors {
    last_report: Option<Instant>,
}

impl SendErrors {
    fn report(&mut self, result: std::io::Result<usize>, destination: SocketAddr, len: usize) {
        if let Err(error) = result {
            let now = Instant::now();
            if self
                .last_report
                .is_some_and(|last| now.duration_since(last) < Duration::from_secs(1))
            {
                return;
            }
            self.last_report = Some(now);
            eprintln!("Dropped {len}-byte UDP packet to {destination}: {error}");
        }
    }
}

impl OPMode {
    fn reverse(self) -> Self {
        match self {
            Self::Obfs => Self::UnObfs,
            Self::UnObfs => Self::Obfs,
        }
    }

    #[inline]
    fn transform(self, buf: &mut [u8], len: usize, key: &[u8; 32]) -> Option<usize> {
        let mut padding = 0;
        let state = match self {
            Self::Obfs => obfs_udp_payload(buf, len, key, &mut padding),
            Self::UnObfs => unobfs_udp_payload(buf, len, key, &mut padding),
        };
        match state {
            ForwardState::NFDrop => None,
            ForwardState::XTContinue => {
                let len = match self {
                    Self::Obfs => len + padding,
                    Self::UnObfs => len - padding,
                };
                (len <= MAX_UDP_PAYLOAD).then_some(len)
            }
        }
    }
}

struct Client {
    socket: Rc<UdpSocket>,
    handle: JoinHandle<()>,
    last_seen: Instant,
}

impl Drop for Client {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn return_packets(
    socket: Rc<UdpSocket>,
    listener: Rc<UdpSocket>,
    client_addr: SocketAddr,
    key: [u8; 32],
    mode: OPMode,
) {
    // Allocate once per client rather than once per packet. Keep the large
    // buffer on the heap so it does not inflate the task's future/stack.
    let mut buf = vec![0u8; PACKET_BUFFER_SIZE];
    let mut send_errors = SendErrors::default();
    loop {
        let mut len = match socket.recv(&mut buf[..MAX_UDP_PAYLOAD]).await {
            Ok(len) => len,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                eprintln!("Receive error for {client_addr}: {e}");
                return;
            }
        };
        for batch_index in 0..RECEIVE_BATCH {
            if let Some(out_len) = mode.transform(&mut buf, len, &key) {
                let result = match listener.try_send_to(&buf[..out_len], client_addr) {
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        listener.send_to(&buf[..out_len], client_addr).await
                    }
                    result => result,
                };
                send_errors.report(result, client_addr, out_len);
            }
            if batch_index + 1 == RECEIVE_BATCH {
                tokio::task::yield_now().await;
                break;
            }
            match socket.try_recv(&mut buf[..MAX_UDP_PAYLOAD]) {
                Ok(next_len) => len = next_len,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => break,
                Err(e) => {
                    eprintln!("Receive error for {client_addr}: {e}");
                    return;
                }
            }
        }
    }
}

async fn new_client(
    bind_addr: SocketAddr,
    args: &AppArgs,
    listener: &Rc<UdpSocket>,
    client_addr: SocketAddr,
) -> std::io::Result<Client> {
    // Apply the same socket buffer sizes in both directions.
    let socket = Rc::new(create_dual_stack_socket(bind_addr)?);
    socket.connect(args.fwd_addr).await?;
    println!("Accepting client {client_addr}");
    let handle = tokio::task::spawn_local(return_packets(
        Rc::clone(&socket),
        Rc::clone(listener),
        client_addr,
        args.key,
        args.obfs_mode.reverse(),
    ));
    Ok(Client {
        socket,
        handle,
        last_seen: Instant::now(),
    })
}

async fn run(args: AppArgs, listener: Rc<UdpSocket>) -> std::io::Result<()> {
    run_with_timeouts(args, listener, CLIENT_TIMEOUT, Duration::from_secs(120)).await
}

async fn run_with_timeouts(
    args: AppArgs,
    listener: Rc<UdpSocket>,
    client_timeout: Duration,
    cleanup_interval: Duration,
) -> std::io::Result<()> {
    println!("rs-wgobfs, a companion to the Linux kernel module xt_wgobfs");
    println!("  Listening on {}", listener.local_addr()?);
    println!(
        "  Obfuscating and forwarding wireguard to {}",
        args.fwd_addr
    );

    // Only this loop owns the registry; no shared locks or atomics are needed.
    let mut clients: HashMap<SocketAddr, Client> = HashMap::new();
    let mut buf = vec![0u8; PACKET_BUFFER_SIZE];
    let mut send_errors = SendErrors::default();
    let mut cleanup = tokio::time::interval(cleanup_interval);
    cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let bind_addr = if args.fwd_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse::<SocketAddr>()
    .unwrap();

    loop {
        let (mut len, mut client_addr) = tokio::select! {
            result = listener.recv_from(&mut buf[..MAX_UDP_PAYLOAD]) => result?,
            _ = cleanup.tick() => {
                let now = Instant::now();
                clients.retain(|_, client| {
                    !client.handle.is_finished() && now.duration_since(client.last_seen) < client_timeout
                });
                continue;
            }
        };

        for batch_index in 0..RECEIVE_BATCH {
            // Incoming keepalives still indicate activity when obfuscation
            // intentionally drops them. Do not create clients for dropped traffic.
            if let Some(client) = clients.get_mut(&client_addr) {
                client.last_seen = Instant::now();
            }
            if let Some(out_len) = args.obfs_mode.transform(&mut buf, len, &args.key) {
                let client = match clients.entry(client_addr) {
                    std::collections::hash_map::Entry::Occupied(mut entry) => {
                        if entry.get().handle.is_finished() {
                            entry.insert(
                                new_client(bind_addr, &args, &listener, client_addr).await?,
                            );
                        }
                        entry.into_mut()
                    }
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(new_client(bind_addr, &args, &listener, client_addr).await?)
                    }
                };
                let result = match client.socket.try_send(&buf[..out_len]) {
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // A new socket may not have registered write readiness
                        // yet. Allow it to become ready, but bound congestion's
                        // effect on other clients and cleanup in this loop.
                        tokio::time::timeout(SEND_TIMEOUT, client.socket.send(&buf[..out_len]))
                            .await
                            .unwrap_or_else(|_| {
                                Err(std::io::Error::new(
                                    std::io::ErrorKind::TimedOut,
                                    "UDP socket was not writable within 1 ms",
                                ))
                            })
                    }
                    result => result,
                };
                send_errors.report(result, args.fwd_addr, out_len);
            }
            if batch_index + 1 == RECEIVE_BATCH {
                // Bound bursts so busy senders cannot starve response tasks/timers.
                tokio::task::yield_now().await;
                break;
            }
            match listener.try_recv_from(&mut buf[..MAX_UDP_PAYLOAD]) {
                Ok((next_len, next_addr)) => {
                    len = next_len;
                    client_addr = next_addr;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => break,
                Err(e) => return Err(e),
            }
        }
    }
}

// A local task set avoids atomic reference counting while retaining the
// single-thread runtime required for OpenBSD and good cache locality.
#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    let args = match parse_args() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("Error: {e}.");
            std::process::exit(1);
        }
    };
    let listener = Rc::new(create_dual_stack_socket(args.local_addr)?);
    tokio::task::LocalSet::new()
        .run_until(run(args, listener))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_expansion_preserves_byte_semantics() {
        assert!(expand_key("").is_err());
        assert_eq!(expand_key("a").unwrap(), [b'a'; 32]);
        assert_eq!(&expand_key("abc").unwrap()[..7], b"abcabca");
        assert_eq!(
            expand_key("01234567890123456789012345678901extra").unwrap(),
            *b"01234567890123456789012345678901"
        );
        let key = expand_key("ключ").unwrap();
        for (i, byte) in key.iter().enumerate() {
            assert_eq!(*byte, "ключ".as_bytes()[i % "ключ".len()]);
        }
    }

    #[tokio::test]
    async fn dropped_keepalives_preserve_client_mapping() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
                let listener = Rc::new(create_dual_stack_socket(bind).unwrap());
                let client = create_dual_stack_socket(bind).unwrap();
                client
                    .connect(listener.local_addr().unwrap())
                    .await
                    .unwrap();
                let peer = create_dual_stack_socket(bind).unwrap();
                let key = [37; 32];
                let task = tokio::task::spawn_local(run_with_timeouts(
                    AppArgs {
                        local_addr: listener.local_addr().unwrap(),
                        fwd_addr: peer.local_addr().unwrap(),
                        key,
                        obfs_mode: OPMode::Obfs,
                    },
                    listener,
                    Duration::from_millis(200),
                    Duration::from_millis(25),
                ));
                let mut packet = [0u8; 64];
                packet[0] = 4;
                client.send(&packet).await.unwrap();
                let mut buf = [0u8; 128];
                let (_, before) =
                    tokio::time::timeout(Duration::from_secs(3), peer.recv_from(&mut buf))
                        .await
                        .unwrap()
                        .unwrap();

                // Send distinct keepalives that obfuscation deliberately drops,
                // for longer than the client's timeout and several cleanup ticks.
                for sequence in 0u64..24 {
                    let keepalive = (0u8..=255)
                        .find_map(|tag| {
                            let mut candidate = [0u8; 32];
                            candidate[0] = 4;
                            candidate[8..16].copy_from_slice(&sequence.to_le_bytes());
                            candidate[16] = tag;
                            let mut scratch = [0u8; 64];
                            scratch[..32].copy_from_slice(&candidate);
                            OPMode::Obfs
                                .transform(&mut scratch, 32, &key)
                                .is_none()
                                .then_some(candidate)
                        })
                        .unwrap();
                    client.send(&keepalive).await.unwrap();
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                assert_eq!(
                    peer.try_recv_from(&mut buf).unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
                client.send(&packet).await.unwrap();
                let (_, after) =
                    tokio::time::timeout(Duration::from_secs(3), peer.recv_from(&mut buf))
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(before, after, "keepalives must preserve the peer socket");
                assert!(!task.is_finished());
                task.abort();
            })
            .await;
    }

    async fn check_udp_route(ip: &str, forward_ip: &str) {
        let bind = format!("{ip}:0").parse().unwrap();
        let echo =
            Rc::new(create_dual_stack_socket(format!("{forward_ip}:0").parse().unwrap()).unwrap());
        let echo_addr = echo.local_addr().unwrap();
        let echo_task = tokio::task::spawn_local(async move {
            let mut buf = vec![0; MAX_UDP_PAYLOAD];
            loop {
                let (len, peer) = echo.recv_from(&mut buf).await.unwrap();
                echo.send_to(&buf[..len], peer).await.unwrap();
            }
        });
        let unobfs_listener = Rc::new(create_dual_stack_socket(bind).unwrap());
        let unobfs_addr = unobfs_listener.local_addr().unwrap();
        let key = [37; 32];
        let unobfs_task = tokio::task::spawn_local(run(
            AppArgs {
                local_addr: unobfs_addr,
                fwd_addr: echo_addr,
                key,
                obfs_mode: OPMode::UnObfs,
            },
            unobfs_listener,
        ));
        let obfs_listener = Rc::new(create_dual_stack_socket(bind).unwrap());
        let obfs_addr = obfs_listener.local_addr().unwrap();
        let obfs_task = tokio::task::spawn_local(run(
            AppArgs {
                local_addr: obfs_addr,
                fwd_addr: unobfs_addr,
                key,
                obfs_mode: OPMode::Obfs,
            },
            obfs_listener,
        ));
        let first = create_dual_stack_socket(bind).unwrap();
        let second = create_dual_stack_socket(bind).unwrap();
        first.connect(obfs_addr).await.unwrap();
        second.connect(obfs_addr).await.unwrap();
        // Malformed traffic must not stop the forwarding loop.
        for len in 0..32 {
            first.send(&vec![0; len]).await.unwrap();
        }
        for size in [64, 92, 148, 200, 201, 1400, 1500, 9000, 65_000] {
            let mut packets = Vec::new();
            for (id, client) in [&first, &second].into_iter().enumerate() {
                let mut packet: Vec<_> = (0..size)
                    .map(|i| (i as u8).wrapping_add(id as u8))
                    .collect();
                packet[..4].copy_from_slice(&[4, 0, 0, 0]);
                if size == 92 {
                    packet[0] = 2;
                    packet[76..92].fill(0);
                } else if size == 148 {
                    packet[0] = 1;
                    packet[132..148].fill(0);
                }
                client.send(&packet).await.unwrap();
                packets.push(packet);
            }
            for (id, client) in [&first, &second].into_iter().enumerate() {
                let mut received = vec![0; PACKET_BUFFER_SIZE];
                let len = tokio::time::timeout(Duration::from_secs(3), client.recv(&mut received))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(&received[..len], &packets[id], "size={size}, client={id}");
            }
        }
        // Bursts larger than a processing batch must preserve each client's
        // payloads and allow both clients' response tasks to make progress.
        for sequence in 0u64..192 {
            for (id, client) in [&first, &second].into_iter().enumerate() {
                let mut packet = [id as u8; 64];
                packet[..4].copy_from_slice(&[4, 0, 0, 0]);
                packet[8..16].copy_from_slice(&sequence.to_le_bytes());
                client.send(&packet).await.unwrap();
            }
        }
        for (id, client) in [&first, &second].into_iter().enumerate() {
            for sequence in 0u64..192 {
                let mut expected = [id as u8; 64];
                expected[..4].copy_from_slice(&[4, 0, 0, 0]);
                expected[8..16].copy_from_slice(&sequence.to_le_bytes());
                let mut received = [0; 128];
                let len = tokio::time::timeout(Duration::from_secs(3), client.recv(&mut received))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(&received[..len], &expected);
            }
        }
        obfs_task.abort();
        unobfs_task.abort();
        echo_task.abort();
    }

    #[tokio::test]
    async fn udp_routes_ipv4_ipv6_and_multiple_clients() {
        tokio::task::LocalSet::new()
            .run_until(async {
                check_udp_route("127.0.0.1", "127.0.0.1").await;
                // IPv6 may be disabled on an otherwise supported host.
                if std::net::UdpSocket::bind("[::1]:0").is_ok() {
                    check_udp_route("[::1]", "[::1]").await;
                    check_udp_route("127.0.0.1", "[::1]").await;
                    check_udp_route("[::1]", "127.0.0.1").await;
                }
            })
            .await;
    }
}
