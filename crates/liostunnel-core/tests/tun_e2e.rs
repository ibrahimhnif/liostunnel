//! T5 (spec §12): the real device on both platforms. Requires root.
//!
//! Neither test here runs by default — both are `#[ignore]`d, and neither
//! touches a routing table or `~/.liostunnel`, so `cargo test --workspace`
//! stays hermetic per the project's test-hygiene rule.
//!
//! macOS: `sudo -E cargo test -p liostunnel-core --test tun_e2e -- --ignored`
//! Linux: same, inside a container/VM run with
//!        `--cap-add=NET_ADMIN --device /dev/net/tun` (or as root on bare
//!        metal/a VM that already has `/dev/net/tun`).
//!
//! These were written and syntax/type-checked (`cargo test --test tun_e2e
//! -- --ignored --list` compiles the binary; `cargo test --test tun_e2e`
//! with no root confirms both show up as `ignored`) but never executed
//! against a real device by the agent that wrote them — that needs root,
//! which this sandbox deliberately does not use. See
//! `testing/gates/README.md` and the Task 22 report for exactly what that
//! means for EC7.

use liostunnel_core::net::tun::{PacketIo, TunConfig, TunDevice};

#[test]
#[ignore = "requires root and a real TUN device"]
fn a_real_tun_device_opens_and_reports_its_name() {
    let dev = TunDevice::open(TunConfig {
        name: None,
        address: std::net::Ipv4Addr::new(10, 91, 0, 1),
        netmask: std::net::Ipv4Addr::new(255, 255, 255, 0),
        mtu: 1500,
    })
    .expect("cannot open TUN — are you root?");

    let name = dev.name().unwrap();
    // EC7: one code path, two platforms, different naming conventions.
    if cfg!(target_os = "macos") {
        assert!(name.starts_with("utun"), "unexpected macOS name: {name}");
    } else {
        assert!(!name.is_empty());
    }
    assert_eq!(dev.mtu(), 1500);
}

#[test]
#[ignore = "requires root and a real TUN device"]
fn packets_sent_to_the_tunnel_subnet_are_read_back_as_bare_ip() {
    let mut dev = TunDevice::open(TunConfig {
        name: None,
        address: std::net::Ipv4Addr::new(10, 92, 0, 1),
        netmask: std::net::Ipv4Addr::new(255, 255, 255, 0),
        mtu: 1500,
    })
    .expect("cannot open TUN — are you root?");

    // Provoke traffic towards the interface. `10.92.0.2` is inside the /24
    // above but has no listener; the kernel routes the echo request to the
    // TUN device regardless (there is nothing else on the interface to
    // answer, and this test does not need a reply — only the outbound
    // packet the OS hands to the device).
    std::process::Command::new("ping")
        .args(["-c", "1", "-W", "1", "10.92.0.2"])
        .output()
        .ok();

    let mut buf = vec![0u8; 2048];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        if std::time::Instant::now() >= deadline {
            panic!("no packet observed on the TUN device within 3s");
        }
        match dev.read_packet(&mut buf) {
            Ok(0) => {}
            Ok(n) => {
                debug_assert!(n > 0, "the Ok(0) arm above already excludes this");
                // The AF prefix must already be stripped: byte 0 is the IP
                // version nibble, not a zero from the utun header. Decision D2.
                assert_eq!(buf[0] >> 4, 4, "expected a bare IPv4 packet");
                break;
            }
            Err(e) => panic!("read_packet returned an error instead of retrying: {e}"),
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}
