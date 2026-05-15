package com.adiza.moviezbox

import android.app.Service
import android.content.ClipData
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.IBinder
import androidx.core.content.FileProvider

class NotificationPollingService : Service() {

    companion object {
        const val CHANNEL_ID_PERSISTENT = "adiza_service_persistent"
        const val CHANNEL_ID_ALERTS     = "adiza_announcements"
        const val SERVICE_NOTIF_ID      = 9001

        @Volatile var instance: NotificationPollingService? = null
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        instance = this
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        instance = null
        super.onDestroy()
    }

    fun fireInstall(apkUri: Uri) {
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(apkUri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            clipData = ClipData.newRawUri("APK", apkUri)
            addFlags(Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
        }
        val resolveList = packageManager.queryIntentActivities(
            intent, PackageManager.MATCH_DEFAULT_ONLY
        )
        for (ri in resolveList) {
            try {
                grantUriPermission(
                    ri.activityInfo.packageName, apkUri, Intent.FLAG_GRANT_READ_URI_PERMISSION
                )
            } catch (_: Exception) {}
        }
        MainActivity.installerLaunched = true
        try { startActivity(intent) } catch (_: Exception) {
            MainActivity.installerLaunched = false
        }
    }
}
