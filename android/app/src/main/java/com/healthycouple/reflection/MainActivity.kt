package com.healthycouple.reflection

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.healthycouple.reflection.data.ReflectionApi
import com.healthycouple.reflection.data.SessionStore
import com.healthycouple.reflection.ui.AuthScreen
import com.healthycouple.reflection.ui.AuthViewModel
import com.healthycouple.reflection.ui.ReflectionScreen
import com.healthycouple.reflection.ui.ReflectionViewModel

/**
 * Single activity hosting the Private Reflection vertical slice.
 *
 * Navigation is intentionally trivial (the only two destinations this slice
 * needs): the auth screen until a session exists, then the reflection screen.
 * There is no broader app navigation — that is out of scope for Phase 2.
 */
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val session = SessionStore(applicationContext)
        val api = ReflectionApi(session)
        val authVm = AuthViewModel(api, session)
        val reflectionVm = ReflectionViewModel(api)

        // Central session-expiry handling: any authed 401 clears the token in
        // the API layer and fires this, which returns the user to login with a
        // clear message and resets the reflection UI so no stale state lingers.
        api.onSessionExpired = {
            authVm.onSessionExpired()
            reflectionVm.reset()
        }

        setContent {
            MaterialTheme {
                Surface {
                    val authState by authVm.state.collectAsStateWithLifecycle()

                    // Navigation is driven purely by auth state: logged in -> the
                    // reflection screen; otherwise the auth screen. Logout flips
                    // that state in the AuthViewModel, so no local latch is needed.
                    if (authState.loggedIn) {
                        ReflectionScreen(
                            vm = reflectionVm,
                            onLogout = authVm::logout,
                        )
                    } else {
                        AuthScreen(vm = authVm)
                    }
                }
            }
        }
    }
}
