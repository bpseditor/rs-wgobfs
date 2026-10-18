//! Local-only UDP round-trip benchmark through an obfs/unobfs pair.
//! Build: rustc --edition=2021 -O tools/benchmark.rs -o /tmp/wgobfs-bench
//! Run: /tmp/wgobfs-bench target/release/rs-wgobfs
//! The reported payload rate counts each completed round trip once; it is
//! affected by the local client, echo server, scheduler, and both proxies.

use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

struct Proxy(Child);
impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn socket() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").unwrap()
}
fn launch(binary: &str, listen: u16, forward: u16, mode: &str) -> Proxy {
    Proxy(
        Command::new(binary)
            .args([
                "-l",
                &format!("127.0.0.1:{listen}"),
                "-f",
                &format!("127.0.0.1:{forward}"),
                "-k",
                "benchmark-key",
                "-m",
                mode,
            ])
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    )
}
fn main() {
    let binary = std::env::args().nth(1).expect("binary path");
    let echo = socket();
    let echo_port = echo.local_addr().unwrap().port();
    echo.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let echo_stop = Arc::clone(&stop);
    let echo_thread = std::thread::spawn(move || {
        let mut buf = [0; 65535];
        while !echo_stop.load(Ordering::Relaxed) {
            match echo.recv_from(&mut buf) {
                Ok((len, addr)) => {
                    echo.send_to(&buf[..len], addr).unwrap();
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => panic!("{e}"),
            }
        }
    });
    let obfs_reservation = socket();
    let unobfs_reservation = socket();
    let obfs_port = obfs_reservation.local_addr().unwrap().port();
    let unobfs_port = unobfs_reservation.local_addr().unwrap().port();
    drop(obfs_reservation);
    drop(unobfs_reservation);
    let mut unobfs = launch(&binary, unobfs_port, echo_port, "unobfs");
    let mut obfs = launch(&binary, obfs_port, unobfs_port, "obfs");
    std::thread::sleep(Duration::from_millis(100));
    assert!(obfs.0.try_wait().unwrap().is_none());
    assert!(unobfs.0.try_wait().unwrap().is_none());
    let client = socket();
    client.connect(("127.0.0.1", obfs_port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut buf = [0; 65535];
    for size in [64, 1400] {
        let mut packet: Vec<u8> = (0..size)
            .map(|i| (i as u8).wrapping_mul(17).wrapping_add(3))
            .collect();
        packet[..4].copy_from_slice(&[4, 0, 0, 0]);
        for trial in 0..3 {
            let started = Instant::now();
            let mut sent = 0;
            let mut received = 0;
            while started.elapsed() < Duration::from_secs(1) {
                for _ in 0..32 {
                    client.send(&packet).unwrap();
                    sent += 1;
                }
                for _ in 0..32 {
                    match client.recv(&mut buf) {
                        Ok(len) => {
                            assert_eq!(&buf[..len], &packet);
                            received += 1;
                        }
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) =>
                        {
                            break
                        }
                        Err(e) => panic!("{e}"),
                    }
                }
            }
            println!("size={size} trial={trial} sent={sent} received={received} roundtrips/s={:.0} payload_mbit/s={:.2}", received as f64 / started.elapsed().as_secs_f64(), received as f64 * size as f64 * 8.0 / started.elapsed().as_secs_f64() / 1e6);
        }
    }
    stop.store(true, Ordering::Relaxed);
    echo_thread.join().unwrap();
}
