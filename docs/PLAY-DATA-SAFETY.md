# Play Console answers

The forms in the Play Console, answered from what the app actually does, so
they are not improvised at submission time. Every answer here is checkable
against the code; where an answer would be embarrassing to defend, that is a
signal to change the code rather than the answer.

## Data safety

**Does your app collect or share any of the required user data types?**
→ **No.**

That is unusual enough that it will be looked at, so the reasoning:

- No analytics, telemetry, crash reporting or advertising SDKs. The full
  dependency list is Flutter, `cupertino_icons`, `flutter_rust_bridge`,
  `freezed_annotation`, `path_provider`, `provider`, and the app's own engine.
- Server profiles and credentials are entered by the user and stay in app-
  private storage. They are not collected, because nothing transmits them
  anywhere.
- Traffic is routed to the user's own server. Play's definition of collection
  covers transmission off the device to the *developer* or a third party; the
  destination here is chosen by the user and is theirs.

**Is data encrypted in transit?** → the tunnel is the point: Shadowsocks AEAD
or SSH.

**Can users request deletion?** → uninstalling removes everything. There is no
server-side copy to request the deletion of.

## VpnService declaration

Mandatory for any app using `VpnService`. Not submitting it is a policy
violation on its own, independent of what the app does.

**Core purpose:** the app is a VPN client. It exists to route the user's
traffic through a server the user configures.

**Does the app use VpnService for its core functionality?** → Yes.

**Confirmations required by the policy, all true here:**

- The VPN is not used to collect personal or sensitive user data without
  consent. It collects none.
- It does not redirect user traffic to a third party for advertising or
  analytics. Traffic goes to the user's configured server and nowhere else.
- It does not manipulate ads.
- It is not a proxy for another app's traffic beyond the VPN's stated purpose.

**Encryption:** Shadowsocks with AEAD ciphers (`aes-128-gcm`, `aes-256-gcm`,
`chacha20-ietf-poly1305`), or SSH with host key verification enabled by
default.

## Content rating

No user-generated content, no ads, no purchases, no social features. Expect
the lowest rating in every category.

## Ads

None.

## Target audience

Adults. Not directed at children.

## Privacy policy URL

Host `docs/PRIVACY.md` somewhere public and paste that URL. GitHub Pages off
this repository is sufficient and keeps it versioned with the code.

## Independent Security Review (MASA)

Not required to publish, and worth considering.

VPN apps are a category with a lot of bad actors in it, so Play surfaces an
"Independent security review" badge in the Data safety section for apps
validated against the Mobile Application Security Verification Standard by an
authorised lab. It costs money and takes time. For an app asking people to
route all their traffic through it, it is the difference between claiming to
be trustworthy and having been checked.
