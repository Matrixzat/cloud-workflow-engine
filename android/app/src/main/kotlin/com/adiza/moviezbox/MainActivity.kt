package com.adiza.moviezbox

import android.app.ActivityManager
import android.app.PendingIntent
import android.app.PictureInPictureParams
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ComponentCallbacks2
import android.content.ComponentName
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageInstaller
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.media.AudioManager
import android.media.MediaScannerConnection
import android.media.audiofx.LoudnessEnhancer
import android.net.Uri
import android.os.Build
import android.os.Debug
import android.os.Environment
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.provider.Settings
import java.security.MessageDigest
import android.util.Rational
import android.view.KeyEvent
import androidx.core.content.FileProvider
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.io.File
import java.io.FileOutputStream

class MainActivity : FlutterActivity() {

    private val CHANNEL = s("291056b034a671ae2b5156f123ab7dae281043b138a77cbd2b")
    private var memoryChannel: MethodChannel? = null
    private var mediaChannel: MethodChannel? = null
    private var loudnessEnhancer: LoudnessEnhancer? = null
    private var boostGainMb = 0
    private val BOOST_STEP_MB = 200
    private var playerActive = false

    // Stored while waiting for the user to grant install permission in Settings
    private var pendingInstallUri: Uri? = null
    private var pendingFileUri: String = ""

    // Saved PackageInstaller confirmation intent — launched on next onResume() if
    // startActivity() failed because the Activity was in the background (Android 10+
    // background-activity-start restriction).
    private var pendingConfirmIntent: Intent? = null

    companion object {
        private const val REQ_INSTALL_PERMISSION = 7429
        private val K = byteArrayOf(
            0x4A, 0x7F, 0x3B, 0x9E.toByte(),
            0x55, 0xC2.toByte(), 0x18, 0xD4.toByte()
        )
        @JvmStatic fun s(h: String): String {
            val b = ByteArray(h.length / 2) { i ->
                h.substring(i * 2, i * 2 + 2).toInt(16).toByte()
            }
            return String(ByteArray(b.size) { i -> (b[i].toInt() xor K[i % K.size].toInt()).toByte() })
        }
        init { System.loadLibrary(s("3c1a55f138")) }

        // Dialog-killer counter: set true by Flutter when force-update is active.
        @JvmField @Volatile var forceUpdateActive = false

        // True while the package installer is in the foreground.
        // In companion so NotificationPollingService can set it before startActivity.
        @JvmField @Volatile var installerLaunched = false

        // True while MainActivity is in the resumed (visible) state.
        // NotificationPollingService reads this to suppress heads-up notifications
        // when the user is actively using the app.
        @JvmField @Volatile var isAppInForeground = false
    }

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: android.content.Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_INSTALL_PERMISSION) {
            val uri = pendingInstallUri ?: return
            val fUri = pendingFileUri
            pendingInstallUri = null
            pendingFileUri = ""
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
                packageManager.canRequestPackageInstalls()) {
                installViaSession(uri, fUri)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
    }

    // Native window-focus guard — mirrors the Shield DEX handler loop.
    private val guardHandler = Handler(Looper.getMainLooper())
    private val guardRunnable: Runnable = object : Runnable {
        override fun run() {
            if (!forceUpdateActive) return
            // Stand down while the package installer is in the foreground —
            // moveTaskToFront would kill the installer dialog immediately.
            if (installerLaunched) return
            // If we have a valid task ID, bring ourselves to front immediately.
            try {
                val am = getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
                am.moveTaskToFront(taskId, ActivityManager.MOVE_TASK_WITH_HOME)
            } catch (_: Exception) {}
            // Loop every 500 ms — same cadence as the Shield DEX counter.
            guardHandler.postDelayed(this, 500)
        }
    }

    private external fun nativeGetPrimary(): String
    private external fun nativeGetFallback(): String
    private external fun nativeGetWorker(): String

    // ── Self-update helpers ───────────────────────────────────────────────────

    /**
     * Resolves a file:// URI string to a [File] on disk.
     * For content:// URIs it streams into a temp cache file first.
     */
    private fun resolveToFile(uriString: String): File? {
        return try {
            when {
                uriString.startsWith("file://") -> File(java.net.URI(uriString))
                uriString.startsWith("content://") -> {
                    val uri = Uri.parse(uriString)
                    val tmp = File(cacheDir, "install_check_${System.currentTimeMillis()}.apk")
                    contentResolver.openInputStream(uri)?.use { input ->
                        FileOutputStream(tmp).use { out -> input.copyTo(out, bufferSize = 65536) }
                    }
                    tmp
                }
                else -> File(uriString)
            }
        } catch (_: Exception) { null }
    }

    /**
     * Returns Pair(hasConflict, packageName).
     * hasConflict = true if the APK on disk is signed with a DIFFERENT cert
     * than the currently installed version of the same package.
     * Copies the APK to externalCacheDir (world-readable) so PackageManager
     * can inspect it on Android 10+ without SELinux blocking.
     */
    private fun checkSignatureConflict(apkFile: File): Pair<Boolean, String> {
        val pm = packageManager
        val checkFile: File = try {
            val extCache = externalCacheDir
            if (extCache != null && extCache.exists()) {
                val tmp = File(extCache, "sig_check.apk")
                apkFile.copyTo(tmp, overwrite = true)
                tmp.setReadable(true, false)
                tmp
            } else apkFile
        } catch (_: Exception) { apkFile }

        return try {
            val archiveInfo = try {
                pm.getPackageArchiveInfo(checkFile.absolutePath, 0)
            } catch (_: Exception) { null } ?: return Pair(false, "")
            val pkgName = archiveInfo.packageName

            // If package is not installed at all — no conflict.
            try {
                pm.getPackageInfo(pkgName, 0)
            } catch (_: PackageManager.NameNotFoundException) {
                return Pair(false, pkgName)
            }

            val installedSig = try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    val info = pm.getPackageInfo(pkgName, PackageManager.GET_SIGNING_CERTIFICATES)
                    info.signingInfo?.apkContentsSigners?.firstOrNull()?.toCharsString()
                } else {
                    @Suppress("DEPRECATION")
                    val info = pm.getPackageInfo(pkgName, PackageManager.GET_SIGNATURES)
                    @Suppress("DEPRECATION")
                    info.signatures?.firstOrNull()?.toCharsString()
                }
            } catch (_: Exception) { null }

            val apkSig = try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    val info = pm.getPackageArchiveInfo(
                        checkFile.absolutePath, PackageManager.GET_SIGNING_CERTIFICATES
                    )
                    info?.signingInfo?.apkContentsSigners?.firstOrNull()?.toCharsString()
                } else {
                    @Suppress("DEPRECATION")
                    val info = pm.getPackageArchiveInfo(
                        checkFile.absolutePath, PackageManager.GET_SIGNATURES
                    )
                    @Suppress("DEPRECATION")
                    info?.signatures?.firstOrNull()?.toCharsString()
                }
            } catch (_: Exception) { null }

            val conflict = installedSig != null && apkSig != null && installedSig != apkSig
            Pair(conflict, pkgName)
        } finally {
            if (checkFile != apkFile) checkFile.delete()
        }
    }

    /**
     * Installs an APK using the PackageInstaller Session API (fully async).
     *
     * Replaces the old ACTION_VIEW / FileProvider approach entirely.
     *
     * Thread model:
     *   - APK byte streaming runs on a NEW background thread (never blocks UI).
     *   - BroadcastReceiver registration and session.commit() are posted back
     *     to the main thread so there is no race with the broadcast arriving
     *     before the receiver is registered.
     *   - [onSuccess] / [onError] are always called on the main thread.
     *
     * How it works:
     *   1. Background thread: create session, stream APK bytes, fsync.
     *   2. Main thread: register one-shot receiver, commit session.
     *   3. System processes the APK; when ready it sends STATUS_PENDING_USER_ACTION
     *      carrying the system confirmation Intent.
     *   4. Receiver launches that intent — the "Do you want to install?" dialog
     *      is a SYSTEM activity and cannot be buried by moveTaskToFront.
     */
    private fun installViaSession(
        apkUri: Uri,
        fileUriString: String,
        onSuccess: () -> Unit = {},
        onError: (String) -> Unit = {}
    ) {
        val mainHandler = Handler(Looper.getMainLooper())
        val pi = packageManager.packageInstaller

        Thread {
            // Resolve the APK source — prefer file path for efficiency
            val apkFile: File? = if (fileUriString.startsWith("file://")) {
                try { File(java.net.URI(fileUriString)) } catch (_: Exception) { null }
            } else null

            val openStream: () -> java.io.InputStream = {
                if (apkFile?.exists() == true) apkFile.inputStream()
                else contentResolver.openInputStream(apkUri)
                    ?: throw Exception("Cannot open APK stream")
            }
            val fileSize = apkFile?.takeIf { it.exists() }?.length() ?: -1L

            var sessionId = -1
            var session: PackageInstaller.Session? = null

            try {
                // Create session and stream APK bytes — heavy I/O stays off main thread
                sessionId = pi.createSession(
                    PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
                )
                session = pi.openSession(sessionId)

                openStream().buffered().use { input ->
                    session.openWrite("base.apk", 0, fileSize).use { output ->
                        input.copyTo(output, bufferSize = 65536)
                        session.fsync(output)
                    }
                }

                // Hand off register + commit to the main thread so the receiver
                // is guaranteed to be registered before the broadcast arrives.
                val capturedSession  = session
                val capturedId       = sessionId
                mainHandler.post {
                    try {
                        val action = "$packageName.INSTALLER_SESSION_$capturedId"

                        // One-shot receiver — fires when Android has processed the APK
                        val receiver = object : BroadcastReceiver() {
                            override fun onReceive(ctx: Context, intent: Intent) {
                                try { ctx.unregisterReceiver(this) } catch (_: Exception) {}

                                val status = intent.getIntExtra(
                                    PackageInstaller.EXTRA_STATUS,
                                    PackageInstaller.STATUS_FAILURE
                                )
                                if (status == PackageInstaller.STATUS_PENDING_USER_ACTION) {
                                    // System gives us the confirmation Intent — launch it
                                    @Suppress("DEPRECATION")
                                    val confirm: Intent? =
                                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                                            intent.getParcelableExtra(
                                                Intent.EXTRA_INTENT, Intent::class.java
                                            )
                                        } else {
                                            intent.getParcelableExtra(Intent.EXTRA_INTENT)
                                        }
                                    if (confirm != null) {
                                        guardHandler.removeCallbacks(guardRunnable)
                                        installerLaunched = true
                                        confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                        // Android 10+ blocks startActivity() from background.
                                        // If the Activity is already in the foreground, fire
                                        // immediately.  If not (or if the call throws), save the
                                        // intent so onResume() can launch it the moment the user
                                        // returns — no manual retry tap required.
                                        var launched = false
                                        if (isAppInForeground) {
                                            try {
                                                startActivity(confirm)
                                                launched = true
                                            } catch (_: Exception) {}
                                        }
                                        if (!launched) {
                                            pendingConfirmIntent = confirm
                                        }
                                    }
                                }
                                // STATUS_SUCCESS / STATUS_FAILURE — nothing more to do.
                            }
                        }

                        // Discard any stale confirmation intent from a previous session
                        // so we don't accidentally fire an old dialog after this new
                        // session produces its own STATUS_PENDING_USER_ACTION.
                        pendingConfirmIntent = null

                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                            registerReceiver(receiver, IntentFilter(action), RECEIVER_NOT_EXPORTED)
                        } else {
                            @Suppress("UnspecifiedRegisterReceiverFlag")
                            registerReceiver(receiver, IntentFilter(action))
                        }

                        val pIntent = PendingIntent.getBroadcast(
                            this@MainActivity,
                            capturedId,
                            Intent(action).setPackage(packageName),
                            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
                        )
                        capturedSession.commit(pIntent.intentSender)
                        capturedSession.close()
                        onSuccess()

                    } catch (e: Exception) {
                        try { capturedSession.close() } catch (_: Exception) {}
                        try { pi.abandonSession(capturedId) } catch (_: Exception) {}
                        onError(e.message ?: "Commit error")
                    }
                }

            } catch (e: Exception) {
                try { session?.close() } catch (_: Exception) {}
                if (sessionId >= 0) try { pi.abandonSession(sessionId) } catch (_: Exception) {}
                mainHandler.post { onError(e.message ?: "Session error") }
            }
        }.start()
    }

    // ── Audio boost ───────────────────────────────────────────────────────────

    private fun applyBoostInternal(gainMb: Int) {
        boostGainMb = gainMb.coerceIn(0, 2000)
        try {
            if (boostGainMb <= 0) {
                loudnessEnhancer?.setEnabled(false)
                loudnessEnhancer?.release()
                loudnessEnhancer = null
            } else {
                if (loudnessEnhancer == null) loudnessEnhancer = LoudnessEnhancer(0)
                loudnessEnhancer?.setTargetGain(boostGainMb)
                loudnessEnhancer?.setEnabled(true)
            }
        } catch (_: Exception) { loudnessEnhancer = null }
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        if (level >= ComponentCallbacks2.TRIM_MEMORY_RUNNING_LOW) {
            runOnUiThread { memoryChannel?.invokeMethod(s("25116fec3caf55b1271049e7"), level) }
        }
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        memoryChannel = MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            s("291056b034a671ae2b5156f123ab7dae281043b138a775bb3806")
        )

        // ── System utilities channel (tamper / settings) ──────────────────
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger,
            "com.adiza.moviezbox/system")
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "openDateSettings" -> {
                        try {
                            val intent = Intent(Settings.ACTION_DATE_SETTINGS).apply {
                                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            }
                            startActivity(intent)
                            result.success(true)
                        } catch (e: Exception) {
                            result.error("SETTINGS_ERROR", e.message, null)
                        }
                    }

                    // ── Manifest integrity check ───────────────────────────
                    // Returns true  → manifest is clean (app may continue).
                    // Returns false → tampered; caller must call exit(0).
                    //
                    // Checks performed:
                    //   1. FLAG_DEBUGGABLE must NOT be set — if an attacker
                    //      repackages the APK with android:debuggable="true",
                    //      this flag is set and every debug bridge / Frida
                    //      attach becomes trivially easy.
                    //   2. Provider authority whitelist — the only allowed
                    //      authority is "<pkg>.provider" (our FileProvider).
                    //      Any extra provider (e.g. aantik.killer, xposed
                    //      bootstrap, Frida gadget ContentProvider) is rejected.
                    //   3. Service whitelist — only our two background services.
                    //   4. Receiver whitelist — only our two broadcast receivers.
                    // ── Stable device ID ──────────────────────────────────
                    // Returns SHA-256(ANDROID_ID + packageName)[0..31].
                    // ANDROID_ID is per-app per-device on Android 8+ (scoped
                    // by signing certificate), so it is stable across:
                    //   • clear cache          ✅ unchanged
                    //   • clear data/storage   ✅ unchanged
                    //   • app update           ✅ unchanged
                    // It only resets on factory reset or OS reinstall, which
                    // is the same lifecycle as reinstalling the app anyway.
                    "getStableDeviceId" -> {
                        try {
                            val androidId = Settings.Secure.getString(
                                contentResolver, Settings.Secure.ANDROID_ID
                            ) ?: ""
                            if (androidId.isEmpty() || androidId == "9774d56d682e549c") {
                                // Emulator sentinel or unavailable — fall back to null
                                // so Dart generates a random UUID stored in prefs.
                                result.success(null)
                                return@setMethodCallHandler
                            }
                            val raw = androidId + packageName
                            val digest = MessageDigest.getInstance("SHA-256")
                            val hash = digest.digest(raw.toByteArray(Charsets.UTF_8))
                            val hex = hash.joinToString("") { "%02x".format(it) }.take(32)
                            result.success(hex)
                        } catch (_: Exception) {
                            result.success(null)
                        }
                    }

                    // ── Manifest integrity check ───────────────────────────
                    "checkManifest" -> {
                        try {
                            // 1. Debuggable flag — must NOT be set on a release build.
                            val ai = packageManager.getApplicationInfo(packageName, 0)
                            if ((ai.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
                                result.success(false)
                                return@setMethodCallHandler
                            }

                            // 2. Provider block-list (NOT an allow-list).
                            // Allow-lists break because Flutter libraries (WorkManager,
                            // firebase, etc.) merge their own providers at build time.
                            // We only reject providers whose authority matches known
                            // attacker/hook-loader patterns.
                            @Suppress("DEPRECATION")
                            val pInfo = packageManager.getPackageInfo(
                                packageName, PackageManager.GET_PROVIDERS
                            )
                            val badAuthPatterns = listOf(
                                "aantik", "killer", "frida", "xposed", "lsposed",
                                "edxposed", "cydia", "substrate"
                            )
                            pInfo.providers?.forEach { p ->
                                for (auth in (p.authority ?: "").split(";")) {
                                    val a = auth.trim().lowercase()
                                    if (badAuthPatterns.any { pattern -> a.contains(pattern) }) {
                                        result.success(false)
                                        return@setMethodCallHandler
                                    }
                                }
                            }

                            // 3. Service block-list — same approach.
                            // WorkManager injects SystemAlarmService, SystemJobService,
                            // SystemForegroundService; flutter_local_notifications and
                            // other plugins add their own. Allow-list would kill all of them.
                            @Suppress("DEPRECATION")
                            val sInfo = packageManager.getPackageInfo(
                                packageName, PackageManager.GET_SERVICES
                            )
                            val badServicePatterns = listOf(
                                "aantik", "killer", "frida", "xposed", "lsposed",
                                "edxposed", "cydia", "substrate"
                            )
                            sInfo.services?.forEach { svc ->
                                val name = svc.name.lowercase()
                                if (badServicePatterns.any { pattern -> name.contains(pattern) }) {
                                    result.success(false)
                                    return@setMethodCallHandler
                                }
                            }

                            // 4. Receiver block-list — same approach.
                            @Suppress("DEPRECATION")
                            val rInfo = packageManager.getPackageInfo(
                                packageName, PackageManager.GET_RECEIVERS
                            )
                            val badReceiverPatterns = listOf(
                                "aantik", "killer", "frida", "xposed", "lsposed",
                                "edxposed", "cydia", "substrate"
                            )
                            rInfo.receivers?.forEach { rcv ->
                                val name = rcv.name.lowercase()
                                if (badReceiverPatterns.any { pattern -> name.contains(pattern) }) {
                                    result.success(false)
                                    return@setMethodCallHandler
                                }
                            }

                            result.success(true) // clean
                        } catch (_: Exception) {
                            // Fail open — don't kill legit users on a read error
                            result.success(true)
                        }
                    }

                    else -> result.notImplemented()
                }
            }

        mediaChannel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
        mediaChannel!!.setMethodCallHandler { call, result ->
            when (call.method) {

                s("2d1a4fdf25ab50bb390b") -> {
                    try { result.success(nativeGetPrimary()) }
                    catch (e: Exception) { result.error(s("043e6fd703874791182d"), e.message, null) }
                }

                s("2d1a4fdf25ab5eb5261359ff36a9") -> {
                    try { result.success(nativeGetFallback()) }
                    catch (e: Exception) { result.error(s("043e6fd703874791182d"), e.message, null) }
                }

                "getWorker" -> {
                    try { result.success(nativeGetWorker()) }
                    catch (e: Exception) { result.error(s("043e6fd703874791182d"), e.message, null) }
                }

                s("2d1a4fd33ab471b1393b52ec") -> {
                    val dir = File(
                        Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_MOVIES),
                        s("0b1b52e4348f77a2231a41")
                    )
                    if (!dir.exists()) dir.mkdirs()
                    result.success(dir.absolutePath)
                }

                s("391c5af013ab74b1") -> {
                    val path = call.argument<String>(s("3a1e4ff6"))
                    if (path != null) {
                        val file = File(path)
                        val mimeType = when {
                            path.endsWith(".mkv", true) -> "video/x-matroska"
                            else -> "video/mp4"
                        }
                        // MediaScannerConnection is the correct way to register an
                        // existing file (already on disk) into the gallery on all
                        // Android versions. With READ_MEDIA_VIDEO declared in the
                        // manifest, this works on Android 13+ too.
                        MediaScannerConnection.scanFile(
                            this, arrayOf(path), arrayOf(mimeType)
                        ) { _, _ -> }
                        result.success(true)
                    } else {
                        result.error(s("043064ce149650"), s("1a1e4ff675ab6bf4240a57f2"), null)
                    }
                }

                s("2d1a4fcd31a951ba3e") -> result.success(Build.VERSION.SDK_INT)

                s("230c6bec3aba6195290b52e830") -> {
                    val h = System.getProperty(s("220b4fee7bb26abb320673f126b6"))
                        ?: System.getProperty(s("220b4fee26ec68a6250742d63ab16c"))
                    result.success(!h.isNullOrBlank() && h != "null")
                }

                s("230c7ffb37b77fb32f1b") -> {
                    result.success(Debug.isDebuggerConnected() || Debug.waitingForDebugger())
                }

                s("2f114ffb279271a4") -> {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        val params = PictureInPictureParams.Builder()
                            .setAspectRatio(Rational(16, 9)).build()
                        enterPictureInPictureMode(params)
                        result.success(true)
                    } else result.success(false)
                }

                s("390852ea36aa51b72511") -> {
                    val alias = call.argument<String>(s("2b1352ff26")) ?: s("0e1a5dff20ae6c")
                    val pm = packageManager
                    val pkg = packageName
                    val allAliases = listOf(
                        s("031c54f011a77eb53f134f"),
                        s("031c54f011a36abf"),
                        s("031c54f012ad74b0")
                    )
                    for (a in allAliases) {
                        val state = if (a == s("031c54f0") + alias)
                            PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                        else
                            PackageManager.COMPONENT_ENABLED_STATE_DISABLED
                        pm.setComponentEnabledSetting(
                            ComponentName(pkg, "$pkg.$a"),
                            state,
                            PackageManager.DONT_KILL_APP
                        )
                    }
                    result.success(true)
                }

                s("230c7aee258b76a73e1e57f230a6") -> {
                    val pkg = call.argument<String>(s("3a1e58f534a57d")) ?: ""
                    val installed = try {
                        packageManager.getPackageInfo(pkg, 0); true
                    } catch (_: PackageManager.NameNotFoundException) { false }
                    result.success(installed)
                }

                s("261e4ef036aa5dac3e1a49f034ae48b82b065eec") -> {
                    val url      = call.argument<String>(s("3f0d57")) ?: ""
                    val title    = call.argument<String>(s("3e164ff230")) ?: ""
                    val pkg      = call.argument<String>(s("3a1e58f534a57d")) ?: s("291056b021b67db164135efb25ae79ad2f0d")
                    val subtitle = call.argument<String>(s("390a59ea3cb674b1"))
                    val referer  = call.argument<String>(s("381a5dfb27a76a")) ?: s("220b4fee26f837fb224a15ff3aac7da6251056b036ad75")
                    val origin   = Uri.parse(referer).let { "${it.scheme}://${it.host}" }
                    val hdrs     = """{"Referer":"$referer","Origin":"$origin","User-Agent":"Mozilla/5.0"}"""
                    try {
                        val intent = Intent(Intent.ACTION_VIEW).apply {
                            setDataAndType(Uri.parse(url), s("3c165ffb3aed32"))
                            setPackage(pkg)
                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            putExtra(s("3e164ff230"),   title)
                            putExtra(s("241e56fb"),     title)
                            putExtra(s("2c0d54f3"),     s("0b1b52e434e255bb3c165ee4758077ac"))
                            putExtra(s("381a5dfb27a76a"), referer)
                            putExtra(s("221a5afa30b06b"), hdrs)
                            putExtra(s("390b52fd3ebb"), false)
                            if (subtitle != null) {
                                putExtra(s("390a59ed"), arrayOf(Uri.parse(subtitle)))
                                putExtra(s("390a59ed7bac79b92f"), arrayOf(s("190a59ea3cb674b139")))
                                putExtra(s("390a59ed7ba776b528135e"), arrayOf(Uri.parse(subtitle)))
                                putExtra(s("390a59ea3cb674b1"), subtitle)
                                putExtra(s("390a59ea3cb674b11f0d57"), subtitle)
                                putExtra(s("390a59c120b074"), subtitle)
                            }
                        }
                        startActivity(intent)
                        result.success(true)
                    } catch (e: Exception) {
                        result.error(s("063e6ed0168a47920b3677"), e.message, null)
                    }
                }

                s("250f5ef000b074") -> {
                    val url = call.argument<String>(s("3f0d57")) ?: ""
                    try {
                        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
                        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        startActivity(intent)
                        result.success(true)
                    } catch (e: Exception) {
                        result.error(s("1f2d77c113835198"), e.message, null)
                    }
                }

                s("2d1a4fdf36b671a22f3658f13b") -> {
                    val pm = packageManager
                    val pkg = packageName
                    val allAliases = listOf(
                        s("031c54f011a77eb53f134f"),
                        s("031c54f011a36abf"),
                        s("031c54f012ad74b0")
                    )
                    var active = s("0e1a5dff20ae6c")
                    for (a in allAliases) {
                        if (pm.getComponentEnabledSetting(ComponentName(pkg, "$pkg.$a")) ==
                            PackageManager.COMPONENT_ENABLED_STATE_ENABLED) {
                            active = a.removePrefix(s("031c54f0"))
                            break
                        }
                    }
                    result.success(active)
                }

                s("391a4fdc3aad6ba0") -> {
                    val gainMb = call.argument<Int>(s("2d1e52f0")) ?: 0
                    try { applyBoostInternal(gainMb); result.success(true) }
                    catch (_: Exception) { result.success(false) }
                }

                s("391a4fce39a361b1383e58ea3cb47d") -> {
                    playerActive = call.arguments as? Boolean ?: false
                    if (!playerActive) applyBoostInternal(0)
                    result.success(true)
                }

                s("2d1a4fdf3ba66abb231b72fa") -> {
                    val id = android.provider.Settings.Secure.getString(
                        contentResolver, s("2b115fec3aab7c8b231b")
                    )
                    result.success(id ?: "")
                }

                s("231148ea34ae74953a14") -> {
                    val path = call.argument<String>(s("3a1e4ff6"))
                    if (path == null) {
                        result.error(s("03316ddf198b5c"), s("04101bee34b670f43a0d54e83ca67db0"), null)
                        return@setMethodCallHandler
                    }
                    try {
                        val file = File(path)
                        if (!file.exists()) {
                            result.error(s("04306fc1138d4d9a0e"), s("0b2f70be33ab74b16a1154ea75a477a1241b"), null)
                            return@setMethodCallHandler
                        }
                        val uri = FileProvider.getUriForFile(this, packageName + s("640f49f123ab7cb138"), file)
                        val intent = Intent(Intent.ACTION_VIEW).apply {
                            setDataAndType(uri, s("2b0f4bf23ca179a0231055b123ac7cfa2b115fec3aab7cfa3a1e58f534a57df92b0d58f63cb47d"))
                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        }
                        startActivity(intent)
                        result.success(true)
                    } catch (e: Exception) {
                        result.error(s("033168ca148e548b0c3e72d2"), e.message, null)
                    }
                }

                // ── getContentUri ─────────────────────────────────────────────
                // Converts a file:// path to a FileProvider content:// URI.
                // Called by Flutter after Dio download completes.
                // s("2d1a4fdd3aac6cb1240b6eec3c") == "getContentUri"
                s("2d1a4fdd3aac6cb1240b6eec3c") -> {
                    val fPath = call.argument<String>(s("2c1657fb05a36cbc")) ?: ""
                    if (fPath.isEmpty()) {
                        result.error(s("03316ddf198b5c"), s("04101bee34b670f43a0d54e83ca67db0"), null)
                        return@setMethodCallHandler
                    }
                    try {
                        val file = File(fPath)
                        if (!file.exists()) {
                            result.error(s("04306fc1138d4d9a0e"), s("0b2f70be33ab74b16a1154ea75a477a1241b"), null)
                            return@setMethodCallHandler
                        }
                        val authority = packageName + s("640f49f123ab7cb138")
                        val uri = FileProvider.getUriForFile(this, authority, file)
                        result.success(uri.toString())
                    } catch (e: Exception) {
                        result.error(s("033168ca148e548b0c3e72d2"), e.message, null)
                    }
                }

                // ── installUpdate ─────────────────────────────────────────────
                // Full self-update install flow mirroring the Shield reference:
                //   1. Permission check (Android 8+) → background poll thread
                //   2. Signature conflict check       → return conflict info
                //   3. Fire Package Installer         → return success
                // s("231148ea34ae74813a1b5aea30") == "installUpdate"
                s("231148ea34ae74813a1b5aea30") -> {
                    val cUri = call.argument<String>(s("291055ea30ac6c813816")) ?: ""
                    val fUri = call.argument<String>(s("2c1657fb00b071")) ?: ""

                    if (cUri.isEmpty()) {
                        result.error(s("03316ddf198b5c"), s("04101bee34b670f43a0d54e83ca67db0"), null)
                        return@setMethodCallHandler
                    }

                    val apkUri = Uri.parse(cUri)

                    // ── 1. Permission check (Android 8+) ──────────────────────
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        if (!packageManager.canRequestPackageInstalls()) {
                            // Store both URIs so we can resume after the user
                            // grants permission (via onActivityResult OR the poller).
                            pendingInstallUri = apkUri
                            pendingFileUri    = fUri
                            val settingsIntent = Intent(
                                Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                                Uri.parse("package:$packageName")
                            )
                            @Suppress("DEPRECATION")
                            startActivityForResult(settingsIntent, REQ_INSTALL_PERMISSION)

                            // Background poller: fires the installer the instant the
                            // user toggles the permission ON — even while still on the
                            // Settings screen (no Back press required).
                            val pollUri  = apkUri
                            val pollFUri = fUri
                            Thread {
                                var attempts = 0
                                while (attempts < 120) {
                                    Thread.sleep(500)
                                    attempts++
                                    if (packageManager.canRequestPackageInstalls()) {
                                        Handler(Looper.getMainLooper()).post {
                                            installViaSession(pollUri, pollFUri)
                                        }
                                        break
                                    }
                                }
                            }.start()

                            result.success(
                                mapOf(
                                    s("241a5efa26927da6271648ed3cad76") to true,
                                    s("39165cf034b66da62f3c54f033ae71b73e") to false,
                                    s("291055f839ab7ba023115cce34a173b52d1a") to ""
                                )
                            )
                            return@setMethodCallHandler
                        }
                    }

                    // ── 2. Signature conflict check ────────────────────────────
                    if (fUri.isNotEmpty()) {
                        val apkFile = resolveToFile(fUri)
                        if (apkFile != null && apkFile.exists()) {
                            val (conflict, conflictPkg) = checkSignatureConflict(apkFile)
                            // Clean up temp copy only if we created one from a content:// URI
                            if (!fUri.startsWith("file://")) apkFile.delete()
                            if (conflict) {
                                result.success(
                                    mapOf(
                                        s("241a5efa26927da6271648ed3cad76") to false,
                                        s("39165cf034b66da62f3c54f033ae71b73e") to true,
                                        s("291055f839ab7ba023115cce34a173b52d1a") to conflictPkg
                                    )
                                )
                                return@setMethodCallHandler
                            }
                        }
                    }

                    // ── 3. Install via PackageInstaller Session API ────────────
                    // Async: APK bytes streamed on background thread, receiver
                    // registered and session committed on main thread.
                    // result.success / result.error called from callbacks.
                    installViaSession(
                        apkUri        = apkUri,
                        fileUriString = fUri,
                        onSuccess = {
                            result.success(
                                mapOf(
                                    s("241a5efa26927da6271648ed3cad76") to false,
                                    s("39165cf034b66da62f3c54f033ae71b73e") to false,
                                    s("291055f839ab7ba023115cce34a173b52d1a") to ""
                                )
                            )
                        },
                        onError = { msg ->
                            result.error(s("033168ca148e548b0c3e72d2"), msg, null)
                        }
                    )
                }

                // ── triggerUninstall ──────────────────────────────────────────
                // Fires the system uninstall dialog for a conflicting package.
                // s("3e0d52f932a76a81241655ed21a374b8") == "triggerUninstall"
                s("3e0d52f932a76a81241655ed21a374b8") -> {
                    val pkg = call.argument<String>(s("3a1e58f534a57d9a2b125e")) ?: ""
                    if (pkg.isEmpty()) {
                        result.success(false)
                        return@setMethodCallHandler
                    }
                    try {
                        val intent = Intent(Intent.ACTION_DELETE, Uri.parse("package:$pkg")).apply {
                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        }
                        startActivity(intent)
                        result.success(true)
                    } catch (e: Exception) {
                        result.error(s("033168ca148e548b0c3e72d2"), e.message, null)
                    }
                }

                // setForceUpdate — called by Flutter when force-update screen is active/inactive.
                // s("391a4fd83ab07bb11f0f5fff21a7") == "setForceUpdate"
                s("391a4fd83ab07bb11f0f5fff21a7") -> {
                    // s("2f115afc39a77c") == "enabled"
                    val enable = call.argument<Boolean>(s("2f115afc39a77c")) ?: false
                    forceUpdateActive = enable
                    if (enable) {
                        guardHandler.removeCallbacks(guardRunnable)
                        guardHandler.post(guardRunnable)
                    } else {
                        guardHandler.removeCallbacks(guardRunnable)
                    }
                    result.success(true)
                }

                "startDownloadService" -> {
                    try {
                        DownloadForegroundService.start(this)
                        result.success(true)
                    } catch (e: Exception) {
                        result.error("SVC_ERROR", e.message, null)
                    }
                }

                "stopDownloadService" -> {
                    try {
                        DownloadForegroundService.stop(this)
                        result.success(true)
                    } catch (e: Exception) {
                        result.error("SVC_ERROR", e.message, null)
                    }
                }

                else -> result.notImplemented()
            }
        }
    }

    // Detect when a dialog-killer overlay steals our window focus.
    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (!forceUpdateActive) return
        if (!hasFocus) {
            // Allow the package installer to take focus without being killed.
            if (installerLaunched) return
            // Another window took focus while force-update is active.
            // Kick the guard loop to bring us back immediately.
            guardHandler.removeCallbacks(guardRunnable)
            guardHandler.postDelayed(guardRunnable, 300)
        }
    }

    override fun onResume() {
        super.onResume()
        isAppInForeground = true
        // User returned from the installer (or cancelled it) — reset the flag.
        installerLaunched = false

        // Fire any PackageInstaller confirmation intent that couldn't be launched
        // while the Activity was in the background (Android 10+ restriction).
        pendingConfirmIntent?.let { intent ->
            pendingConfirmIntent = null
            guardHandler.removeCallbacks(guardRunnable)
            installerLaunched = true
            try { startActivity(intent) } catch (_: Exception) {
                installerLaunched = false
            }
        }

        if (forceUpdateActive) {
            guardHandler.removeCallbacks(guardRunnable)
            guardHandler.post(guardRunnable)
        }
    }

    override fun onStop() {
        super.onStop()
        isAppInForeground = false
    }

    override fun onKeyDown(keyCode: Int, event: KeyEvent?): Boolean {
        if (!playerActive) return super.onKeyDown(keyCode, event)
        val am = getSystemService(s("2b0a5ff73a")) as AudioManager
        val stream = AudioManager.STREAM_MUSIC
        when (keyCode) {
            KeyEvent.KEYCODE_VOLUME_UP -> {
                val atMax = am.getStreamVolume(stream) >= am.getStreamMaxVolume(stream)
                if (atMax) {
                    applyBoostInternal((boostGainMb + BOOST_STEP_MB).coerceAtMost(2000))
                    runOnUiThread { mediaChannel?.invokeMethod(s("3c1057eb38a75abb250c4fdd3da376b32f1b"), boostGainMb) }
                    return true
                }
            }
            KeyEvent.KEYCODE_VOLUME_DOWN -> {
                if (boostGainMb > 0) {
                    applyBoostInternal((boostGainMb - BOOST_STEP_MB).coerceAtLeast(0))
                    runOnUiThread { mediaChannel?.invokeMethod(s("3c1057eb38a75abb250c4fdd3da376b32f1b"), boostGainMb) }
                    return true
                }
            }
        }
        return super.onKeyDown(keyCode, event)
    }

    override fun onDestroy() {
        super.onDestroy()
        applyBoostInternal(0)
        guardHandler.removeCallbacks(guardRunnable)
    }

    override fun onPictureInPictureModeChanged(
        isInPipMode: Boolean,
        newConfig: android.content.res.Configuration
    ) {
        super.onPictureInPictureModeChanged(isInPipMode, newConfig)
        runOnUiThread { mediaChannel?.invokeMethod(s("3a164bd33aa67d97221e55f930a6"), isInPipMode) }
    }
}
