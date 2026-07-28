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
    let mut seen = 0usize;
    let mut saw_provoked_v4 = false;

    loop {
        if std::time::Instant::now() >= deadline {
            break;
        }
        match dev.read_packet(&mut buf) {
            Ok(0) => {}
            Ok(n) => {
                debug_assert!(n > 0, "the Ok(0) arm above already excludes this");
                seen += 1;

                // The property under test: the AF prefix is already stripped,
                // so byte 0 is a real IP version nibble rather than a zero from
                // the utun header. Decision D2.
                //
                // Deliberately accepts 4 OR 6. An earlier version of this test
                // asserted IPv4 specifically and failed the first time it was
                // ever run against a real device: Linux emits IPv6 link-local
                // traffic (a router solicitation / MLD report) the moment the
                // interface comes up, so the provoked ICMP echo is not the
                // first packet off the device. Both versions are bare IP, which
                // is what this test exists to prove.
                let version = buf[0] >> 4;
                assert!(
                    version == 4 || version == 6,
                    "expected a bare IP packet, got version nibble {version} \
                     (a 0 here would mean the AF prefix leaked through)"
                );

                // If this is the echo request we provoked, confirm it is the
                // one we asked for rather than incidental traffic.
                if version == 4 && n >= 20 && buf[16..20] == [10, 92, 0, 2] {
                    saw_provoked_v4 = true;
                    break;
                }
            }
            Err(e) => panic!("read_packet returned an error instead of retrying: {e}"),
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    assert!(seen > 0, "no packet observed on the TUN device within 3s");
    // Not asserted as a hard requirement: on a host with IPv6 disabled the
    // provoked echo is the only traffic, while on a normal host it arrives
    // after the kernel's own link-local chatter. Either way `seen > 0` above
    // has already proven the framing property this test is named for.
    if !saw_provoked_v4 {
        eprintln!(
            "note: {seen} packet(s) read, none of them the provoked ICMP echo to 10.92.0.2; \
             the bare-IP framing assertion still held for every packet"
        );
    }
}
