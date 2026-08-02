# LiosTunnel privacy policy

*Last updated: 2 August 2026*

LiosTunnel is a tunnel client. It routes your device's traffic to a server
**you** configure and control. There is no LiosTunnel service, no account, no
server operated by us, and nothing to sign up for.

## What we collect

Nothing.

The app has no analytics, no telemetry, no crash reporting and no advertising
identifiers. It contains no third-party SDKs that could collect anything: its
entire dependency list is Flutter itself, three UI and code-generation
packages, `path_provider`, and its own Rust engine.

No data is transmitted to the developer, because there is nowhere for it to be
transmitted to.

## What stays on your device

- **Server profiles** — the host, port, protocol and settings you enter.
- **Credentials** — the Shadowsocks password or SSH key for each profile.
- **SSH host keys**, remembered so a changed key is noticed.

All of it lives in the app's private storage, readable only by this app, and is
deleted when you uninstall it. None of it is backed up to us, because again,
there is no us to back it up to.

## Your traffic

While connected, your device's traffic is routed through the server named in
the profile you selected — and nowhere else. The app's own connection to that
server is excluded from the tunnel, so it does not route through itself.

**We cannot see your traffic.** It goes from your device to your server. If you
want to know what happens to it after that, the answer is determined by
whoever runs the server, which is you.

## Logging

The app writes a small number of diagnostic lines to the Android system log:
connection state changes, byte and flow counts, and error messages.

**It never logs the content of your traffic, the addresses you visit, or the
names you look up.** This is enforced in the code rather than left to
configuration — the rule that no payload byte, DNS name or secret reaches any
log, error message or debug output is applied throughout the engine, including
its error strings.

These logs stay on your device and are not transmitted anywhere.

## Permissions

The app requests four, and no others:

| Permission | Why |
|---|---|
| `INTERNET` | to reach the server you configured |
| `FOREGROUND_SERVICE` | to keep the tunnel running when the app is not on screen |
| `FOREGROUND_SERVICE_SPECIAL_USE` | required by Android 14+ for the above |
| `POST_NOTIFICATIONS` | the ongoing notification shown while the tunnel is up |

It also uses Android's `VpnService`, which requires your explicit consent
through a system dialog the first time you connect. Android shows a key icon in
the status bar the whole time a VPN is active.

There is no location, contacts, storage or camera access, because none is
needed.

## Children

The app is not directed at children and collects nothing from anyone.

## Changes

Material changes will be reflected here with a new date. The history of this
file is public in the repository.

## Source

The client is open source, engine included. Claims made here can be checked
against the code rather than taken on trust.

## Contact

Open an issue on the repository.
