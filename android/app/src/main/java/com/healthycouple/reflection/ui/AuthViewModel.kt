package com.healthycouple.reflection.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.healthycouple.reflection.data.ApiResult
import com.healthycouple.reflection.data.ReflectionApi
import com.healthycouple.reflection.data.SessionStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** UI state for the authentication screen. */
data class AuthUiState(
    val loading: Boolean = false,
    val error: String? = null,
    val loggedIn: Boolean = false,
)

/**
 * Handles register + login for the slice. Registration is a convenience so a
 * tester can create an account and immediately land in the reflection flow;
 * both paths end in a persisted session token.
 */
class AuthViewModel(
    private val api: ReflectionApi,
    session: SessionStore,
) : ViewModel() {

    private val _state = MutableStateFlow(AuthUiState(loggedIn = session.isLoggedIn))
    val state: StateFlow<AuthUiState> = _state.asStateFlow()

    fun login(identifier: String, password: String) = run(register = false, identifier, password)

    fun registerAndLogin(identifier: String, password: String) =
        run(register = true, identifier, password)

    private fun run(register: Boolean, identifier: String, password: String) {
        if (identifier.isBlank() || password.isBlank()) {
            _state.value = _state.value.copy(error = "Enter an email and password.")
            return
        }
        _state.value = _state.value.copy(loading = true, error = null)
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                if (register) {
                    when (val r = api.register(identifier, password)) {
                        is ApiResult.Err -> r
                        is ApiResult.Ok -> api.login(identifier, password)
                    }
                } else {
                    api.login(identifier, password)
                }
            }
            _state.value = when (result) {
                is ApiResult.Ok -> AuthUiState(loading = false, loggedIn = true)
                is ApiResult.Err -> _state.value.copy(loading = false, error = result.message)
            }
        }
    }

    fun clearError() {
        _state.value = _state.value.copy(error = null)
    }
}
