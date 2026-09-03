package com.healthycouple.reflection.data

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * On-device storage for the session token.
 *
 * The session token (`<session_id>.<token>`) is the credential the backend
 * issues at login and the app presents as `Authorization: Bearer <token>` on
 * every authenticated request. It is stored in [EncryptedSharedPreferences] so
 * it is encrypted at rest on the device rather than sitting in plaintext prefs.
 *
 * This is deliberately minimal — just what the Private Reflection slice needs to
 * stay authenticated between screens and app launches.
 */
class SessionStore(context: Context) {

    private val prefs by lazy {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            "hc_session",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    var sessionToken: String?
        get() = prefs.getString(KEY_TOKEN, null)
        set(value) {
            prefs.edit().apply {
                if (value == null) remove(KEY_TOKEN) else putString(KEY_TOKEN, value)
            }.apply()
        }

    val isLoggedIn: Boolean get() = sessionToken != null

    fun clear() {
        sessionToken = null
    }

    private companion object {
        const val KEY_TOKEN = "session_token"
    }
}
