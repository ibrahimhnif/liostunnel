# Runs the Phase 1a verification on Linux, where Phase 0's engine is known to
# carry traffic. Joins the fixture network so the SSH server and the nginx
# target are both reachable, and gets exactly the capabilities the helper
# needs: NET_ADMIN and NET_RAW for the TUN device and routes, and /dev/net/tun.
#
# Built FROM the same rust image that compiles the helper. A plain
# debian:bookworm base is a newer-glibc mismatch — the binary built by
# rust:1.93-slim wants GLIBC_2.38/2.39 and bookworm ships 2.36, so it will not
# even start. Same base, same libc, no surprises.
FROM rust:1.93-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 curl python3 procps sudo tcpdump ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 # Real unprivileged accounts to act as the client and as an intruder. The
 # helper must serve exactly one uid and refuse every other, so this needs two
 # actual users rather than everything running as root.
 && useradd -m -u 1500 lios \
 && useradd -m -u 1501 intruder

WORKDIR /w
ENTRYPOINT ["/bin/bash"]
