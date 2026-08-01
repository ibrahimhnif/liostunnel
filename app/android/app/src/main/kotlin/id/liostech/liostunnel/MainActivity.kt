package id.liostech.liostunnel

import android.content.Intent
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {

    private var vpn: VpnChannel? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        val channel = VpnChannel(this)
        vpn = channel
        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            VpnChannel.CHANNEL,
        ).setMethodCallHandler(channel)
    }

    /**
     * The VPN consent dialog answers here, not on the channel that raised it.
     * Without this override the `prepare` call never completes and the UI waits
     * forever on a dialog the user already answered.
     */
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        vpn?.onActivityResult(requestCode, resultCode)
    }
}
