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

        /** Asks a running service to tear the tunnel down. See onStartCommand. */
        const val ACTION_DISCONNECT = "com.liostunnel.app.DISCONNECT"


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

    /** Guards [teardown] against running twice. */
    private var tornDown = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Stopping has to be asked for from inside the service.
        //
        // `stopService` from the Activity does not destroy a VpnService whose
        // tunnel is established: the VPN framework holds its own reference, so
        // the call returns having done nothing. Measured, not assumed --
        // Disconnect appeared to do nothing at all, with no error and no log,
        // while the tunnel stayed up and the notification stayed put.
        if (intent?.action == ACTION_DISCONNECT) {
            Log.i(TAG, "disconnect requested")
            // Tear down here rather than leaving it to onDestroy. stopSelf()
            // alone does not destroy the service either: the VPN stays up
            // until the tunnel descriptor is closed, and that descriptor now
            // belongs to the engine. Closing it is what brings the interface
            // down, which is what lets the service finish.
            teardown()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }

        startForeground(NOTIFICATION_ID, buildNotification())

        // Before establish(), and before any socket exists: this hands native
        // code the JavaVM and a reference to this service, which is what
        // protect(fd) is called through. Without it every protect fails and
        // the tunnel's own transport routes into itself.
        nativeInit()

        val pfd = establishTunnel()
        if (pfd == null) {
            // `establish()` returns null when consent was revoked or another
            // VPN took over. Stopping loudly beats running a service with no
            // tunnel behind it.
            Log.e(TAG, "establish() returned null; stopping")
            stopSelf()
            return START_NOT_STICKY
        }

        tornDown = false
        tunnel = pfd
        // Ownership of the descriptor transfers to native code. Nothing on
        // this side may close it while the engine holds it -- see onDestroy.
        nativeStart(pfd.detachFd())

        // Not START_STICKY: a restart hands onStartCommand a null intent, and
        // there is no staged profile then -- the engine would refuse and the
        // tunnel would be a shell. A tunnel should come back because someone
        // asked for it, not because the process died.
        return START_NOT_STICKY
    }

    private fun establishTunnel(): ParcelFileDescriptor? =
        Builder()
            .setSession("LiosTunnel")
            // Read from Rust, not written twice. This address and
            // `StackConfig::address` must be the same one: the smoltcp stack
            // answers on it, and if the interface carries a different address
            // the tunnel silently carries nothing. Hardcoding it here is how
            // that drift starts, and it did — this said 10.0.0.2 while the
            // stack used 10.90.0.1.
            .addAddress(nativeTunAddress(), 32)
            // Everything. `protect()` is what keeps the tunnel's own transport
            // out of this route; there is no narrower route that would do the
            // job, because the whole point is to carry arbitrary traffic.
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
            .setMtu(nativeTunMtu())
            .establish()

    /**
     * Stops the engine and releases the tunnel.
     *
     * Idempotent: the disconnect path calls it and so does [onDestroy], which
     * still runs afterwards, and `nativeStop` on an already-stopped engine
     * would otherwise try to join a runtime that is gone.
     */
    @Synchronized
    private fun teardown() {
        if (tornDown) return
        tornDown = true
        // Before closing the descriptor: nativeStop blocks until the engine's
        // threads have joined, so nothing is still reading when this returns.
        nativeStop()
        tunnel?.close()
        tunnel = null
    }

    override fun onDestroy() {
        teardown()
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

    private external fun nativeInit()
    private external fun nativeStart(fd: Int)
    private external fun nativeStop()

    /** The address the packet stack answers on. Single source of truth. */
    private external fun nativeTunAddress(): String

    /** The MTU the packet stack expects, for the same reason. */
    private external fun nativeTunMtu(): Int

}
