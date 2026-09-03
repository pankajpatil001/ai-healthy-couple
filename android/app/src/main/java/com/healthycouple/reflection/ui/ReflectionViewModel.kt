package com.healthycouple.reflection.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.healthycouple.reflection.data.ApiResult
import com.healthycouple.reflection.data.Reflection
import com.healthycouple.reflection.data.ReflectionApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * UI state for the single-reflection screen.
 *
 * The slice manages exactly one reflection at a time (there is no list
 * endpoint): [reflection] null + not loading = the empty state (nothing written
 * yet); [loading] gates spinners; [error] carries a user-facing, privacy-safe
 * message.
 */
data class ReflectionUiState(
    val loading: Boolean = false,
    val reflection: Reflection? = null,
    val error: String? = null,
    val editing: Boolean = false,
) {
    val isEmpty: Boolean get() = !loading && reflection == null && error == null
}

class ReflectionViewModel(
    private val api: ReflectionApi,
) : ViewModel() {

    private val _state = MutableStateFlow(ReflectionUiState())
    val state: StateFlow<ReflectionUiState> = _state.asStateFlow()

    fun startNew() {
        _state.value = ReflectionUiState(editing = true)
    }

    fun startEdit() {
        _state.value = _state.value.copy(editing = true, error = null)
    }

    fun cancelEdit() {
        _state.value = _state.value.copy(editing = false, error = null)
    }

    /** Create a new reflection, or save edits to the current one. */
    fun save(content: String) {
        if (content.isBlank()) {
            _state.value = _state.value.copy(error = "Write something first.")
            return
        }
        val current = _state.value.reflection
        _state.value = _state.value.copy(loading = true, error = null)
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                if (current == null) api.create(content) else api.update(current.id, content)
            }
            _state.value = when (result) {
                is ApiResult.Ok -> ReflectionUiState(reflection = result.value, editing = false)
                is ApiResult.Err -> _state.value.copy(loading = false, error = result.message)
            }
        }
    }

    fun refresh(id: String) {
        _state.value = _state.value.copy(loading = true, error = null)
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) { api.get(id) }
            _state.value = when (result) {
                is ApiResult.Ok -> ReflectionUiState(reflection = result.value)
                is ApiResult.Err -> _state.value.copy(loading = false, error = result.message)
            }
        }
    }

    fun delete() {
        val current = _state.value.reflection ?: return
        _state.value = _state.value.copy(loading = true, error = null)
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) { api.delete(current.id) }
            _state.value = when (result) {
                is ApiResult.Ok -> ReflectionUiState() // back to empty state
                is ApiResult.Err -> _state.value.copy(loading = false, error = result.message)
            }
        }
    }

    fun clearError() {
        _state.value = _state.value.copy(error = null)
    }
}
