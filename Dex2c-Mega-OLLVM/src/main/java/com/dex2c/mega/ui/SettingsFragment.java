package com.dex2c.mega.ui;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.Toast;
import androidx.appcompat.widget.SwitchCompat;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import com.dex2c.mega.R;

public class SettingsFragment extends Fragment {

    public static final String PREFS_NAME       = "dex2c_prefs";
    public static final String KEY_LIBRARY_NAME = "library_name";
    public static final String KEY_ABI_ARM64         = "abi_arm64_v8a";
    public static final String KEY_ABI_ARMEABI       = "abi_armeabi_v7a";
    public static final String KEY_ABI_X86_64        = "abi_x86_64";
    public static final String KEY_ABI_X86           = "abi_x86";
    /** When false, ApkProtector writes sentinel stamps (0,0) so guard.cpp skips the check. */
    public static final String KEY_MANIFEST_DEX_CHECK = "manifest_dex_check";
    /**
     * When true, ApkProtector extracts the META-INF signing certificate from the
     * input APK, SHA-256s the raw bytes, and bakes the digest into font_kern.dat.
     * guard.cpp then verifies the installed APK signature on every load — using
     * a direct syscall (bypassing libc IO hooks / SRPatch IO method) so tools
     * like SRPatch, NP Manager PMS hook, and LSPatch cannot spoof the result.
     *
     * IMPORTANT: the input APK must already be signed BEFORE protection.
     * Using Dex2c Mega's own built-in signer is NOT compatible with this check
     * because signing happens after protection — the cert won't match.
     */
    public static final String KEY_SIG_CHECK = "sig_check";

    public static final String DEFAULT_LIBRARY_NAME = "dex2c-mega";

    private EditText etLibraryName;
    private CheckBox cbArm64, cbArmeabi, cbX86_64, cbX86;
    private SwitchCompat swManifestDex;
    private SwitchCompat swSigCheck;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_settings, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        etLibraryName = view.findViewById(R.id.et_library_name);
        cbArm64        = view.findViewById(R.id.cb_arm64_v8a);
        cbArmeabi      = view.findViewById(R.id.cb_armeabi_v7a);
        cbX86_64       = view.findViewById(R.id.cb_x86_64);
        cbX86          = view.findViewById(R.id.cb_x86);
        swManifestDex  = view.findViewById(R.id.sw_manifest_dex_check);
        swSigCheck     = view.findViewById(R.id.sw_sig_check);

        loadSettings();

        view.findViewById(R.id.btn_save_settings).setOnClickListener(v -> saveSettings());
    }

    private SharedPreferences prefs() {
        return requireContext().getSharedPreferences(PREFS_NAME, android.content.Context.MODE_PRIVATE);
    }

    private void loadSettings() {
        SharedPreferences p = prefs();
        etLibraryName.setText(p.getString(KEY_LIBRARY_NAME, DEFAULT_LIBRARY_NAME));
        // both default ON — user can toggle either off
        cbArm64.setChecked(p.getBoolean(KEY_ABI_ARM64, true));
        cbArmeabi.setChecked(p.getBoolean(KEY_ABI_ARMEABI, true));
        // x86_64 / x86 hidden — not shown to user, always false
        cbX86_64.setChecked(false);
        cbX86.setChecked(false);
        swManifestDex.setChecked(p.getBoolean(KEY_MANIFEST_DEX_CHECK, true));
        swSigCheck.setChecked(p.getBoolean(KEY_SIG_CHECK, true));
    }

    private void saveSettings() {
        String name = etLibraryName.getText().toString().trim();
        if (TextUtils.isEmpty(name)) {
            Toast.makeText(requireContext(), "Library name cannot be empty", Toast.LENGTH_SHORT).show();
            return;
        }
        if (!name.matches("[A-Za-z0-9_-]+")) {
            Toast.makeText(requireContext(),
                    "Only letters, numbers, hyphens and underscores are allowed",
                    Toast.LENGTH_SHORT).show();
            return;
        }

        prefs().edit()
                .putString(KEY_LIBRARY_NAME, name)
                .putBoolean(KEY_ABI_ARM64,   cbArm64.isChecked())
                .putBoolean(KEY_ABI_ARMEABI, cbArmeabi.isChecked())
                .putBoolean(KEY_ABI_X86_64,  false)   // not supported
                .putBoolean(KEY_ABI_X86,     false)   // not supported
                .putBoolean(KEY_MANIFEST_DEX_CHECK, swManifestDex.isChecked())
                .putBoolean(KEY_SIG_CHECK,   swSigCheck.isChecked())
                .apply();

        Toast.makeText(requireContext(), "Settings saved", Toast.LENGTH_SHORT).show();
    }
}
