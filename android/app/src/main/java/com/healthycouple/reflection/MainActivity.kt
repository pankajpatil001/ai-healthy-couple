package com.healthycouple.reflection

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
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

        setContent {
            MaterialTheme {
                Surface {
                    val authState by authVm.state.collectAsStateWithLifecycle()
                    // Track logout locally so we can flip back to the auth screen.
                    var loggedOut by remember { mutableStateOf(false) }

                    if (authState.loggedIn && !loggedOut) {
                        ReflectionScreen(
                            vm = reflectionVm,
                            onLogout = {
                                api.logout()
                                loggedOut = true
                            },
                        )
                    } else {
                        // Reset the logout latch once we're back on the auth screen.
                        if (loggedOut) loggedOut = false
                        AuthScreen(vm = authVm)
                    }
                }
            }
        }
    }
}
