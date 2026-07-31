package com.liostunnel.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

/**
 * The Dart-facing control surface for the tunnel.
 *
 * **No method here takes a credential.** `start` carries no arguments at all:
 * by the time it is called the engine already holds the profile, loaded over
 * FFI. Adding a parameter to `start` would put a password into an `Intent`,
 * which is exactly what this shape exists to prevent.
 */
class VpnChannel(private val activity: Activity) : MethodChannel.MethodCallHandler {

    companion object {
        const val CHANNEL = "com.liostunnel.app/vpn"
        const val REQUEST_CONSENT = 9001
    }

    /**
     * The `prepare` call awaiting the consent dialog's result.
     *
     * Held rather than replied to immediately because the answer arrives on
     * `onActivityResult`, an entirely different callback.
     */
    private var pendingConsent: MethodChannel.Result? = null

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "prepare" -> prepare(result)
            "start" -> {
                activity.startForegroundService(
                    Intent(activity, LiosVpnService::class.java)
                )
                result.success(null)
            }
            "stop" -> {
                activity.stopService(Intent(activity, LiosVpnService::class.java))
                result.success(null)
            }
            else -> result.notImplemented()
        }
    }

    private fun prepare(result: MethodChannel.Result) {
        // Returns null when consent has already been granted -- the common
        // case after first run, and one that must not raise a dialog.
        val intent = VpnService.prepare(activity)
        if (intent == null) {
            result.success(true)
            return
        }
        // A second `prepare` while one is outstanding would strand the first
        // call forever, since only one result can be delivered.
        pendingConsent?.success(false)
        pendingConsent = result
        activity.startActivityForResult(intent, REQUEST_CONSENT)
    }

    fun onActivityResult(requestCode: Int, resultCode: Int) {
        if (requestCode != REQUEST_CONSENT) return
        // Anything other than RESULT_OK is a refusal, including the user
        // dismissing the dialog with the back gesture.
        pendingConsent?.success(resultCode == Activity.RESULT_OK)
        pendingConsent = null
    }
}
