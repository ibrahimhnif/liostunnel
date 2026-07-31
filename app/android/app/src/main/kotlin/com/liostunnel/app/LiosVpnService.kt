package com.liostunnel.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log

/**
 * The tunnel's Android host.
 *
 * Its only jobs are to obtain a tunnel file descriptor and to keep the process
 * alive. It holds no profile, no credential and no engine state: the engine
 * already has the profile, loaded over FFI before this service was ever
 * started.
 *
 * That split is deliberate. An `Intent` extra can be written to the system log
 * and `MethodChannel` arguments are ordinary Java objects visible in a heap
 * dump, so a password put here would be outside our control. The only thing
 * that crosses into Kotlin is a descriptor number.
 */
class LiosVpnService : VpnService() {

    companion object {
        private const val TAG = "liostunnel"
        private const val CHANNEL_ID = "liostunnel"
        private const val NOTIFICATION_ID = 1

        /**
         * JNI resolves `external fun` against libraries the *JVM* has loaded.
         *
         * Dart loads this same `.so` through `DynamicLibrary.open` for FFI, but
         * that is invisible to JNI — without this call every `native*` method
         * below throws `UnsatisfiedLinkError` the moment the service starts,
         * long after the app has built and installed cleanly.
         */
        init {
            System.loadLibrary("liostunnel_ffi")
        }
    }

    private var tunnel: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIFICATION_ID, buildNotification())

        val pfd = establishTunnel()
        if (pfd == null) {
            // `establish()` returns null when consent was revoked or another
            // VPN took over. Stopping loudly beats running a service with no
            // tunnel behind it.
            Log.e(TAG, "establish() returned null; stopping")
            stopSelf()
            return START_NOT_STICKY
        }

        tunnel = pfd
        // Ownership of the descriptor transfers to native code. Nothing on
        // this side may close it while the engine holds it -- see onDestroy.
        nativeStart(pfd.detachFd())
        return START_STICKY
    }

    private fun establishTunnel(): ParcelFileDescriptor? =
        Builder()
            .setSession("LiosTunnel")
            .addAddress("10.0.0.2", 32)
            // Everything. `protect()` is what keeps the tunnel's own transport
            // out of this route; there is no narrower route that would do the
            // job, because the whole point is to carry arbitrary traffic.
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
            .setMtu(1500)
            .establish()

    override fun onDestroy() {
        // Before closing the descriptor: the engine is still reading from it
        // until this returns.
        nativeStop()
        tunnel?.close()
        tunnel = null
        super.onDestroy()
    }

    /** The system also calls this when the user revokes VPN permission. */
    override fun onRevoke() {
        Log.i(TAG, "VPN permission revoked")
        stopSelf()
        super.onRevoke()
    }

    private fun buildNotification(): Notification {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "LiosTunnel",
                NotificationManager.IMPORTANCE_LOW,
            )
            getSystemService(NotificationManager::class.java)
                .createNotificationChannel(channel)
        }
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("LiosTunnel")
            .setContentText("Tunnel active")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .build()
    }

    private external fun nativeStart(fd: Int)
    private external fun nativeStop()
}
