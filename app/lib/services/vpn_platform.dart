import 'package:flutter/services.dart';

/// The Dart side of the Android VPN control channel.
///
/// **Nothing here carries a credential.** The profile, including its password
/// or key, reaches the engine over FFI before [start] is called; this channel
/// only asks Android to raise the consent dialog and to run the service. A
/// parameter added to [start] would end up in an `Intent`, where the system
/// may log it.
///
/// Android-only. Every method throws [MissingPluginException] elsewhere, so
/// callers must gate on the platform rather than relying on a silent no-op.
class VpnPlatform {
  const VpnPlatform._();

  static const _channel = MethodChannel('com.liostunnel.app/vpn');

  /// Raises the system VPN consent dialog when consent has not been given.
  ///
  /// Returns true when the tunnel may be established. False means the user
  /// declined — which is an answer, not an error, and must not be retried on
  /// its own.
  static Future<bool> prepare() async =>
      await _channel.invokeMethod<bool>('prepare') ?? false;

  /// Starts the foreground service, which establishes the tunnel and hands
  /// its descriptor to the engine.
  ///
  /// Call [prepare] first: without consent `establish()` returns null and the
  /// service stops itself.
  static Future<void> start() => _channel.invokeMethod<void>('start');

  /// Stops the service, which tears down the tunnel and the notification.
  static Future<void> stop() => _channel.invokeMethod<void>('stop');
}
