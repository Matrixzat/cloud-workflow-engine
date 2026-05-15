package com.adiza.moviezbox

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Fires when this package is replaced (i.e. after a successful self-update).
 * Automatically relaunches the app so the user lands straight in the new version
 * without having to tap the "Open" button on the installer screen.
 */
class SelfUpdateReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        val launch = context.packageManager
            .getLaunchIntentForPackage(context.packageName) ?: return
        launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        context.startActivity(launch)
    }
}
