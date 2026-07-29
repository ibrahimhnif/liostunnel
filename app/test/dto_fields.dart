// Shared by the tests that assert on what a `ProfileDto` actually carries.
//
// Not a `_test.dart` file on purpose: `flutter test` collects those, and this
// declares no tests.
import 'package:liostunnel_app/src/rust/dto/profile.dart';

/// Every string a [ProfileDto] carries, joined.
///
/// The DTO crosses the FFI and is rendered on screen, so the thing worth
/// asserting is that no field of it holds secret material. `'$dto'` cannot
/// say that: the generated class overrides `==` and `hashCode` but not
/// `toString`, so it prints `Instance of 'ProfileDto'` and any assertion
/// against it passes no matter what the fields contain.
String everyFieldOf(ProfileDto d) => [
      d.id,
      d.name,
      d.protocol,
      d.host,
      '${d.port}',
      d.authKind,
      d.authSecretSource,
      d.authPassphraseSource ?? '',
      d.peerPublicKey ?? '',
      d.cipher ?? '',
      d.dnsMode,
      ...d.dnsServers,
      d.dohSni ?? '',
      d.dohPath ?? '',
      d.splitTunnel,
      ...d.splitTunnelApps,
      '${d.killSwitch}',
    ].join(' ');
