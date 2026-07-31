# LiosTunnel

LiosTunnel is a cross-platform tunneling application that routes your device traffic through secure remote tunnels. It combines a Flutter user interface with a shared Rust networking core to deliver consistent behavior across desktop and Android.

## What the app does

- Creates secure tunnels using **SSH** or **Shadowsocks** server profiles
- Captures traffic through a virtual TUN interface
- Sends DNS queries through the tunnel (DNS over TCP or DNS over HTTPS)
- Supports full-tunnel and selected-route traffic modes
- Validates and manages profiles with secret references for safer credential handling

## How LiosTunnel works

1. You configure or import a server profile.
2. LiosTunnel validates the profile and credentials before connecting.
3. The app establishes a tunnel transport to the remote server.
4. Traffic is redirected to the local TUN interface.
5. The Rust core forwards packets through the active tunnel and applies DNS strategy through the tunnel path.
6. On disconnect, routes and runtime network state are reverted.

### Platform runtime model

- **macOS / Linux (Desktop):** the app communicates with a privileged helper service that manages routing and tunnel operations.
- **Android:** tunnel operations run inside the app process using the Android VPN model.

## Release artifacts

LiosTunnel release outputs are platform specific:

- **macOS:** `.pkg` installer
- **Linux:** `.AppImage`
- **Android:** ABI-specific `.apk` files (for example `arm64-v8a`)

Build and packaging scripts are provided under `/home/runner/work/liostunnel/liostunnel/packaging`, and verification scripts are available under `/home/runner/work/liostunnel/liostunnel/testing`.

## CLI quick usage

```bash
# Validate a profile
liostunnel validate myserver.liostunnel.json

# Probe server reachability/authentication before full routing
liostunnel probe myserver.liostunnel.json --user me --dest example.com:80

# Connect with selected routes
sudo liostunnel connect myserver.liostunnel.json --user me \
  --route-mode test --cidr 93.184.216.0/24 --capture-dns

# Connect with default routing
sudo liostunnel connect myserver.liostunnel.json --user me --route-mode default
```

## Security model (summary)

- Host key verification is enabled by default for SSH.
- Secrets are referenced from files and checked with strict permissions.
- Tunnel payloads are not logged as plaintext.

## Repository references

- Product requirements: `/home/runner/work/liostunnel/liostunnel/PRD.md`
- App source: `/home/runner/work/liostunnel/liostunnel/app`
- Rust crates: `/home/runner/work/liostunnel/liostunnel/crates`
- Packaging scripts: `/home/runner/work/liostunnel/liostunnel/packaging`
- Verification assets: `/home/runner/work/liostunnel/liostunnel/testing`
