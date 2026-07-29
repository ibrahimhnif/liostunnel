# Phase 1b exit criteria — verification

Branch `phase1b-shadowsocks`. Fixture: `make -C testing/docker up` brings up
`ss-libev` (C reference, `aes-256-gcm`, 8388) and `ss-rust` (Rust,
`chacha20-ietf-poly1305`, 8389).

| Criterion | Status |
|---|---|
| P1b-1 — connects and carries traffic | ✅ protocol layer **and** end-to-end |
| P1b-2 — interoperates with libev | ✅ |
| P1b-3 — a wrong password fails at connect | ✅ |
| P1b-4 — `ss://` imports; malformed refused without echo | ✅ |
| P1b-5 — the ownership gate covers SS passwords | ✅ unit **and** end-to-end |
| P1b-6 — no SSH-shaped concession, or it is recorded | ✅ recorded below |

All verbatim output. §7 is the end-to-end run, on macOS 15.5 (Darwin 25.5.0).

---

## P1b-1 — connects and carries traffic

```
$ cargo test -p liostunnel-core --test shadowsocks_integration -- --ignored
test the_probe_reaches_a_resolver_only_the_relay_can_reach ... ok
test connects_to_the_c_reference_implementation ... ok
test connects_to_the_rust_server_with_a_chacha_cipher ... ok
test relays_a_real_http_request_to_a_target_only_it_can_reach ... ok
test a_wrong_password_fails_at_connect ... ok
test the_wrong_cipher_against_a_real_server_also_fails_at_connect ... ok
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 8.27s
```

`relays_a_real_http_request_to_a_target_only_it_can_reach` is the one that
carries traffic. It targets the fixture's nginx on the compose network, whose
port the host does not publish, requires the response to contain
`tunnel-target-ok`, and asserts the byte counters moved **by a delta measured
after `connect`**. The delta matters: `connect` runs the probe, which moves 19
bytes up and 2 down through the same counters, so the absolute values are
non-zero before the HTTP exchange begins and asserting `> 0` on them said
nothing at all.

**The counter delta, not reachability, is what proves the relay carried the
bytes.** `CountingStream` wraps only streams that came out of
`ProxyClientStream`, so a byte counted is a byte the Shadowsocks server
relayed. An earlier version asserted the target is unreachable from the host;
that is a property of the platform, not of the code — Docker Desktop does not
route compose networks to the host, native Linux Docker does — so it passed
here and would have failed in CI for a reason having nothing to do with the
tunnel. It is now reported, not asserted.

The plan named `93.184.216.34` for this. That was example.com's address and has
since been retired, so the test would have failed for a reason having nothing
to do with the tunnel — and would have made the result depend on the machine's
own internet access. The compose address is discovered with `docker inspect`,
not hardcoded: it moves on every `make down`/`make up`. The fixture also
carries its own resolver, so no test here needs outbound internet from the
machine running it.

**A/B.** With `probe` short-circuited to `Ok(())`, the connect tests stay green
and both credential tests fail. With the probe's stream detached from the
counters, both relay-proof tests fail.

## P1b-2 — interoperates with libev

`connects_to_the_c_reference_implementation`, above. This is the criterion the
two-server fixture exists for: a shadowsocks-rust client against a
shadowsocks-rust server proves the crate agrees with itself, which is the same
shape as a mock written to match the code it tests. libev is the C reference.

`connects_to_the_rust_server_with_a_chacha_cipher` adds the second axis — a
different implementation *and* a different cipher family, so a client hardcoded
to one of them fails here rather than at a user's machine.

## P1b-3 — a wrong password fails at connect

`a_wrong_password_fails_at_connect` and
`the_wrong_cipher_against_a_real_server_also_fails_at_connect`, above.

**This criterion produced the finding of the phase, and only a real server
could produce it.**

Shadowsocks has no handshake, so without the probe `connect` returns `Ok` for a
typo'd password: the UI reports Connected, routes get installed, and nothing
carries. The probe sends one DNS query over a relayed stream and requires bytes
back — a wrong-key server cannot produce readable bytes, because every chunk
goes through an AEAD tag check.

What the live servers showed is **which** failure arrives. The loopback
fixtures hang up on a bad key, so they reach the probe's `read_exact` arm and
return `TunnelError::Auth`. A real `ss-libev` server does not hang up. It
accepts the connection and discards the bytes silently — which is precisely the
behaviour the probe was written to work around — so the probe runs out of time
instead and returns `TunnelError::Transport(TimedOut)`.

So the arm a real user actually hits was the one whose message said nothing
about credentials. The message now names both causes, in the order a real
server implies:

> nothing came back through the tunnel in time: the cipher or password may be
> wrong (a Shadowsocks server given either accepts the connection and discards
> it silently), or the exit cannot reach the resolver this profile names

**Resolved after the whole-branch review.** `dispatch::connect_failed` maps
every non-`Auth` `TunnelError` to `ErrorKind::Internal`, rendered as *"The
helper hit an internal error. Check its log."* — so the most common user error
in this protocol read as a helper fault. The timeout arm now returns
`TunnelError::Config { field: "auth", … }`, which the same dispatch already
routes to `ErrorKind::BadRequest`. No new `ErrorKind`, no FFI change.

The probe also now tries **every** resolver in `dns.servers` rather than only
the first, dividing its ceiling across them — with a single outer ceiling a
first resolver that swallows the query spends the whole budget and the loop
never reaches the second.

## P1b-4 — `ss://` imports; malformed refused without echo

```
$ cargo test -p liostunnel-core --lib ss_uri
test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 240 filtered out
```

An `ss://` URI **contains the password**, which makes `ss_uri.rs` the most
leak-prone file in the phase. The enforcement is structural rather than
per-message: `bad(reason: &'static str)` is the only error constructor in the
module, so a `format!` cannot pass through it, and a reviewer can check that by
eye. `no_error_exit_echoes_any_part_of_the_uri` drives every exit with a marker
password and asserts on `Display`, `Debug` **and** `source()`.

Both link forms parse, including SIP002's optional trailing `/` — every Outline
access key carries one, and the parser previously died on it reporting *"the
port is not a number"* about a perfectly good port. The fix is scoped to the
SIP002 branch: stripping `/` from the shared body would silently truncate a
legacy standard-alphabet blob, whose base64 contains `/` as data.

The password leaves the parser in `Redacted<String>` and reaches Dart through a
call separate from the profile, so it never enters `ProfileDto` — the value the
UI renders. `everyFieldOf` in the Dart suite enumerates all 17 DTO fields and
asserts none carries it.

A fourth echo sink was identified here that nobody had named: `expect` on
secret-derived data. `FromUtf8Error`'s `Debug` prints the raw bytes, so a panic
on a decoded credential puts it in the log.

## P1b-5 — the ownership gate covers SS passwords

```
$ cargo test -p liostunnel-helper shadowsocks
test session::tests::a_shadowsocks_password_the_caller_does_not_own_is_refused_by_the_same_rule ... ok
test session::tests::a_shadowsocks_profile_the_caller_owns_passes_the_gate_untouched ... ok
test session::tests::a_shadowsocks_profile_gets_a_shadowsocks_tunnel ... ok
test session::tests::a_shadowsocks_cipher_name_is_never_echoed_back_either ... ok
test session::tests::a_shadowsocks_dns_sni_is_never_echoed_back_either ... ok
test dispatch::tests::a_shadowsocks_probe_failure_is_not_reported_as_a_wrong_password ... ok
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 57 filtered out
```

The point of this criterion is that **no new code was needed**. A Shadowsocks
password is a `SecretRef`, so `AuthMethod::secret_refs()` enumerates it and
Phase 1a's escalation gate covers it unchanged — `authorize_params` is still a
single loop over `profile.auth.secret_refs()` with no protocol branch in it. A
second rule for a second protocol is how the two drift.

This is also the one place a missing match arm would have been a privilege
escalation rather than a compile error, since `secret_refs()` is the list the
root daemon iterates to decide whether it may read a file on a caller's behalf.
The A/B for Task 1 confirmed the arm's absence is caught: `refs.len()` goes 1 →
0.

## P1b-6 — the abstraction test

**Did `Protocol` need an SSH-shaped concession? Yes — one, and it was real.
Closing it improved the abstraction rather than bending it.**

**Resolved with no trait change: `HostKeyPolicy`.** Meaningless for a protocol
with no server identity. It sat in `Tunnel::start`'s shared body; it now lives
inside the `ProtocolKind::Ssh` arm. No residue in the neutral path. This is
what the abstraction working looks like.

**The real hole: `Protocol` exposes no peer address.** The route that pins the
server through the original gateway needs the server's concrete IP. `SshTunnel`
knows it — `peer_addr()` returns the address the session actually connected to,
and that method exists because an earlier review found the alternative, a second
independent DNS lookup, can disagree with the session for a multi-A or
dual-stack host: the pin names one address while the traffic uses another, and
in `default` route mode the tunnel's own packets then route into the tunnel.

The trait cannot express this, so the factory first shipped as
`Result<(Arc<dyn Protocol>, Option<SocketAddr>), StartError>` — the `Option`
existing solely because one concrete type could answer a question the trait
could not. The Shadowsocks arm returned `None`.

**That `None` turned out to be a Critical bug, not a cosmetic gap.**
`ServerConfig::new((host, port), …)` always yields `ServerAddr::DomainName`, so
the shadowsocks crate re-resolves **per flow**, through the helper process's OS
resolver — which `default` route mode has just pointed *into the tunnel*. For a
multi-A host the pin covers only the first address and flows landing on the
others are swallowed by the tunnel's own stack; and independently of multi-A,
resolving the server's own name requires a relayed flow that requires resolving
the server's name. It works only while the OS DNS cache holds the pre-route
lookup. At TTL expiry the tunnel wedges with no default route left on the
machine, and it reads as a server fault.

Fixed at the root rather than papered over: `ShadowsocksTunnel::connect`
resolves once through `pick_ipv4` and hands `ServerConfig` a concrete
`SocketAddr`, so the crate never looks up again, and exposes `peer_addr()` like
`SshTunnel`. Consequences:

- the factory's return type collapsed to `(Arc<dyn Protocol>, SocketAddr)`;
- `pick_ipv4` moved from `protocols::ssh` to `protocols::`, so the neutral path
  no longer imports from the SSH module — it was never SSH policy, it encodes
  the packet stack's IPv4-only constraint;
- both protocols now give the route layer the same guarantee.

**The residue, stated plainly.** `peer_addr()` is an inherent method on both
concrete types, not a trait method. `connect_protocol` works only because each
arm knows its concrete type and both happen to have one. A third protocol that
does not would reintroduce the `Option`. The recommended amendment is a
defaulted trait method:

```rust
/// The concrete address this session is actually using, where the protocol
/// knows it. `None` means the caller must resolve, and accepts that the
/// answer may differ from the one in use.
fn peer_addr(&self) -> Option<SocketAddr> { None }
```

That is a spec decision, not something this phase enacted.

**Two more holes in the same trait, found by the whole-branch review and not by
the P1b-6 exercise itself** — recorded because the omission is part of the
answer:

- **`disconnect(&mut self)` is unreachable through `Arc<dyn Protocol>`**, which
  is what the factory returns. No shipping teardown path calls it at all. This
  is the same question one method over — "what can the factory's return type
  express?" — and the exercise that found `peer_addr` should have found it.
- **`open_tcp_stream_named` / `open_dns_stream_named` are inherent `SshTunnel`
  methods with no trait counterpart.** Relaying by name keeps the destination
  lookup inside the tunnel, and Shadowsocks supports it natively
  (`Address::DomainNameAddress`) — so this is a capability both protocols have
  that the trait cannot express. It is why the CLI's `probe` stays SSH-only and
  why the Shadowsocks relay test has to discover an IP with `docker inspect`.

So the honest answer to P1b-6 is: the abstraction held for the thing the phase
set out to test, and the second protocol revealed three separate places where
`Protocol` cannot say what both implementations know.

---

## §7 — end-to-end through the helper (root)

The Phase 1a verifier, pointed at a Shadowsocks profile. Run on macOS
15.5 against the Docker fixture.

```
$ LIOS_PROFILE=/tmp/lios-verify/ss-profile.json sudo -E ./testing/verify-phase1a.sh
wire   : protocol_version 2, protocol shadowsocks

=== P1a-6 — a secret the caller does not own is refused, with nothing created ===
  bait: 600 owned by uid 0
  {"type":"error","id":2,"kind":"secret_not_permitted",
   "message":"secret file /tmp/lios-verify/rootkey is not owned by uid 501"}
  PASS  root-owned secret refused
  PASS  no TUN device created
  PASS  no route installed

=== P1a-6b — an env-var secret is refused (it would read ROOT's environment) ===
  {"type":"error","id":2,"kind":"bad_request",
   "message":"env-var secrets are not available through the helper"}
  PASS  env-var secret refused

=== P1a-2, P1a-3, P1a-4 — a real tunnel, live stats, and surviving the client ===
  connect reply: [{"type": "ack", "id": 2}, {"type": "state", "state": "Connected"}]
  PASS  P1a-2: connect brought up a real tunnel
  stats before traffic: {'bytes_up': 0, 'bytes_down': 0, 'active_flows': 0, ...}
  stats after traffic : {'bytes_up': 464, 'bytes_down': 1156, 'active_flows': 0, ...}
  PASS  P1a-3: 4/4 fetches returned and bytes came back through the engine
  packets on the tunnel device during those fetches:
    listening on utun9, link-type NULL (BSD loopback)
    IP 10.90.0.1.54772 > 192.168.158.4.80: Flags [SEW], ...
    IP 10.90.0.1.54772 > 192.168.158.4.80: Flags [P.], ... HTTP: GET / HTTP/1.1
    IP 192.168.158.4.80 > 10.90.0.1.54772: Flags [P.], ... HTTP: HTTP/1.1 200 OK

=== P1a-4 — the tunnel outlives the client that started it ===
  route: 192.168.158.4/32   utun9              USc                 utun9
  PASS  a fresh client re-synced to the still-running tunnel

=== teardown ===
  PASS  default route unchanged throughout
  PASS  no interface left behind
  PASS  no tunnel or utun route survived teardown
  PASS  every revert command succeeded

=== 15 passed, 0 failed ===
```

**P1b-1 end-to-end.** `bytes_up: 464, bytes_down: 1156` for the same four
fetches Phase 1a measured over SSH on this machine — **the identical byte
counts**. That is not a coincidence and it is not a tally reading its own
output: the counters wrap the inner stream, so the same payload through a
completely different transport moves the same bytes. The `tcpdump` capture on
`utun9` is the independent witness — a real SYN, a real `GET / HTTP/1.1`, a
real `HTTP/1.1 200 OK`, on the tunnel device.

**P1b-5 end-to-end.** `secret_not_permitted: secret file
/tmp/lios-verify/rootkey is not owned by uid 501` — for a **Shadowsocks**
profile, from the ownership branch specifically, with no TUN device created
and no route installed. The gate needed no new code; `secret_refs()`
enumerating the Shadowsocks password was the whole change.

### What the script needed, and whether it is a P1b-6 finding

§7's rule: *if the script needs an edit to pass, that edit is a P1b-6
finding.* It needed two, and both are worth separating from the abstraction
question:

1. **The two escalation-gate checks built their bait profiles inline as SSH**,
   regardless of `$LIOS_PROFILE`. Unfixed, "14 passed" on a Shadowsocks run
   would have been evidence about SSH. This is a **test-harness** limitation,
   not a `Protocol` concession — nothing in the product needed changing, only
   the script's assumption that there is one protocol.
2. **The wire version was hardcoded** in six places. Unrelated to protocols;
   it made a stale binary look like five unrelated failures, which is exactly
   what happened on the first attempt.

Neither is a concession the abstraction had to make. The tunnel itself, the
route pin, the state file, the reconnect path and the teardown all ran
unchanged against a second protocol — which is the evidence the criterion was
asking for.

## Decisions this phase defers to the review

1. **`ErrorKind` for a probe timeout — RESOLVED, no new variant.** The probe's
   timeout arm now returns `TunnelError::Config { field: "auth", … }`, which
   `dispatch.rs` already routes to `ErrorKind::BadRequest` — the arm added this
   phase for exactly this reasoning, "a profile the user can fix, not a helper
   fault". The message names both causes. Zero FFI change, zero Dart change.

2. **`Protocol::disconnect` is not called on any shipping teardown path** —
   **corrected after the whole-branch review.** This was recorded as
   "`disconnect` leaves open flows relaying, while `SshTunnel` gets teardown
   for free from `SSH_MSG_DISCONNECT`". That comparison is false as shipped.
   `Tunnel::drop` reverts routes, shuts down the stack and aborts the engine
   task; it never touches the protocol, and `Engine` holds
   `Arc<dyn Protocol>`, through which `disconnect(&mut self)` cannot be called
   at all. The only callers in the tree are `cli/commands/probe.rs` and the
   SSH integration tests. So **both** protocols behave identically on
   teardown: nothing is signalled, and in-flight flows end only because the
   stack shutdown kills their `LocalStream`.
   The decision is therefore not "build live-stream tracking" but "either drop
   `disconnect` from `Protocol` or give the teardown path a handle through
   which it can be called". Recorded, not enacted — it is a trait change with
   no user-visible symptom now that flows are bounded in time.

3. **The probe contacts `dns.servers[0]` only — RESOLVED.** It now iterates
   every entry and succeeds on the first that answers, dividing the 8s ceiling
   across them: with only an outer ceiling, a first resolver that swallows the
   query spends the whole budget and the loop never reaches the second, which
   is the exact failure it exists to fix.
