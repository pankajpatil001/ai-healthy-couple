package com.healthycouple.reflection.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.healthycouple.reflection.data.ApiResult
import com.healthycouple.reflection.data.Reflection
import com.healthycouple.reflection.data.ReflectionApi
import com.healthycouple.reflection.data.ReflectionSummary
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Which screen the reflection feature is showing. */
enum class Screen { LIST, DETAIL, EDIT }

/**
 * UI state for the whole reflection feature.
 *
 * The app is now list-first: [items] holds the owner's reflection summaries;
 * [selected] is the currently-open reflection (decrypted) on the detail/edit
 * screen. [screen] drives navigation between the list and a single item.
 */
data class ReflectionUiState(
    val screen: Screen = Screen.LIST,
    val loading: Boolean = false,
    val items: List<ReflectionSummary> = emptyList(),
    val selected: Reflection? = null,
    val error: String? = null,
) {
    val isListEmpty: Boolean get() = !loading && items.isEmpty()
    /** True while composing a brand-new reflection (edit screen, no selection). */
    val isNew: Boolean get() = screen == Screen.EDIT && selected == null
}

class ReflectionViewModel(
    private val api: ReflectionApi,
) : ViewModel() {

    private val _state = MutableStateFlow(ReflectionUiState())
    val state: StateFlow<ReflectionUiState> = _state.asStateFlow()

    // -- list -------------------------------------------------------------

    /** Load (or reload) the owner's reflections and show the list screen. */
    fun loadList() {
        _state.value = _state.value.copy(loading = true, error = null, screen = Screen.LIST)
        viewModelScope.launch {
            when (val r = withContext(Dispatchers.IO) { api.list() }) {
                is ApiResult.Ok -> _state.value = ReflectionUiState(
                    screen = Screen.LIST, items = r.value,
                )
                is ApiResult.Err -> _state.value = _state.value.copy(
                    loading = false, error = r.message,
                )
            }
        }
    }

    // -- open / new -------------------------------------------------------

    /** Open an existing reflection: fetch decrypted content, show detail. */
    fun open(id: String) {
        _state.value = _state.value.copy(loading = true, error = null, screen = Screen.DETAIL)
        viewModelScope.launch {
            when (val r = withContext(Dispatchers.IO) { api.get(id) }) {
                is ApiResult.Ok -> _state.value = _state.value.copy(
                    loading = false, selected = r.value, screen = Screen.DETAIL,
                )
                is ApiResult.Err -> _state.value = _state.value.copy(
                    loading = false, error = r.message, screen = Screen.LIST,
                )
            }
        }
    }

    /** Begin composing a new reflection. */
    fun startNew() {
        _state.value = _state.value.copy(screen = Screen.EDIT, selected = null, error = null)
    }

    /** Edit the currently-open reflection. */
    fun startEdit() {
        if (_state.value.selected != null) {
            _state.value = _state.value.copy(screen = Screen.EDIT, error = null)
        }
    }

    /** Leave edit/detail and return to the list (reloading it). */
    fun backToList() {
        loadList()
    }

    // -- mutations --------------------------------------------------------

    /** Create a new reflection or save edits to the open one, then reload list. */
    fun save(content: String) {
        if (content.isBlank()) {
            _state.value = _state.value.copy(error = "Write something first.")
            return
        }
        val current = _state.value.selected
        _state.value = _state.value.copy(loading = true, error = null)
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                if (current == null) api.create(content) else api.update(current.id, content)
            }
            when (result) {
                is ApiResult.Ok -> {
                    // Show the saved item on the detail screen, then refresh the
                    // list in the background so it stays consistent.
                    _state.value = _state.value.copy(
                        loading = false, selected = result.value, screen = Screen.DETAIL,
                    )
                    refreshItemsSilently()
                }
                is ApiResult.Err -> _state.value = _state.value.copy(
                    loading = false, error = result.message,
                )
            }
        }
    }

    /** Delete the open reflection, then return to the (reloaded) list. */
    fun delete() {
        val current = _state.value.selected ?: return
        _state.value = _state.value.copy(loading = true, error = null)
        viewModelScope.launch {
            when (val r = withContext(Dispatchers.IO) { api.delete(current.id) }) {
                is ApiResult.Ok -> loadList()
                is ApiResult.Err -> _state.value = _state.value.copy(
                    loading = false, error = r.message,
                )
            }
        }
    }

    private fun refreshItemsSilently() {
        viewModelScope.launch {
            (withContext(Dispatchers.IO) { api.list() } as? ApiResult.Ok)?.let {
                _state.value = _state.value.copy(items = it.value)
            }
        }
    }

    fun clearError() {
        _state.value = _state.value.copy(error = null)
    }

    /** Reset to a clean list state (e.g. after logout). */
    fun reset() {
        _state.value = ReflectionUiState()
    }
}
