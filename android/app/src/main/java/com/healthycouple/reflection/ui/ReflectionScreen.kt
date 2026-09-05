package com.healthycouple.reflection.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.healthycouple.reflection.data.ReflectionSummary

/**
 * The Private Reflection feature UI. List-first:
 *
 *  - LIST: the owner's reflections (loaded from the backend on entry), with a
 *    "+ New Reflection" action and an empty state.
 *  - DETAIL: a selected reflection's decrypted content, with Edit / Delete.
 *  - EDIT: compose a new reflection or edit the open one.
 *
 * The privacy notice is always visible. State is kept consistent by reloading
 * the list after every create / update / delete.
 */
@Composable
fun ReflectionScreen(vm: ReflectionViewModel, onLogout: () -> Unit) {
    val state by vm.state.collectAsStateWithLifecycle()

    // Load the list once when the screen first appears.
    LaunchedEffect(Unit) { vm.loadList() }

    Column(modifier = Modifier.fillMaxSize().padding(24.dp)) {
        HeaderRow(
            title = when (state.screen) {
                Screen.LIST -> "Private Reflections"
                Screen.DETAIL -> "Reflection"
                Screen.EDIT -> if (state.isNew) "New reflection" else "Edit reflection"
            },
            showBack = state.screen != Screen.LIST,
            onBack = vm::backToList,
            onLogout = onLogout,
        )
        PrivacyNotice()
        Spacer(Modifier.padding(8.dp))

        state.error?.let { ErrorText(it) }

        Box(modifier = Modifier.fillMaxSize()) {
            when {
                state.loading -> LoadingState()
                state.screen == Screen.EDIT -> EditState(
                    initial = state.selected?.content.orEmpty(),
                    isNew = state.isNew,
                    onSave = vm::save,
                    onCancel = vm::backToList,
                )
                state.screen == Screen.DETAIL && state.selected != null -> DetailState(
                    content = state.selected!!.content,
                    onEdit = vm::startEdit,
                    onDelete = vm::delete,
                )
                state.isListEmpty -> EmptyState(onStart = vm::startNew)
                else -> ListState(
                    items = state.items,
                    onOpen = vm::open,
                    onNew = vm::startNew,
                )
            }
        }
    }
}

@Composable
private fun HeaderRow(
    title: String,
    showBack: Boolean,
    onBack: () -> Unit,
    onLogout: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (showBack) {
            TextButton(onClick = onBack) { Text("< Back") }
        } else {
            Text(title, style = MaterialTheme.typography.titleLarge)
        }
        TextButton(onClick = onLogout) { Text("Log out") }
    }
}

@Composable
private fun PrivacyNotice() {
    Card(modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(Icons.Filled.Lock, contentDescription = null)
            Spacer(Modifier.padding(6.dp))
            Text(
                "Private to you. Your reflections are never automatically shared " +
                    "with your partner.",
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}

@Composable
private fun LoadingState() {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        CircularProgressIndicator()
    }
}

@Composable
private fun EmptyState(onStart: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("You haven't written a reflection yet.")
        Button(onClick = onStart) { Text("Write a reflection") }
    }
}

@Composable
private fun ListState(
    items: List<ReflectionSummary>,
    onOpen: (String) -> Unit,
    onNew: () -> Unit,
) {
    Box(modifier = Modifier.fillMaxSize()) {
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(items, key = { it.id }) { summary ->
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onOpen(summary.id) },
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            "Reflection",
                            style = MaterialTheme.typography.titleMedium,
                        )
                        Text(
                            "Updated ${summary.updatedAt}",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
        }
        ExtendedFloatingActionButton(
            onClick = onNew,
            icon = { Icon(Icons.Filled.Add, contentDescription = null) },
            text = { Text("New Reflection") },
            modifier = Modifier.align(Alignment.BottomEnd).padding(16.dp),
        )
    }
}

@Composable
private fun DetailState(content: String, onEdit: () -> Unit, onDelete: () -> Unit) {
    var confirmDelete by remember { mutableStateOf(false) }

    Column(modifier = Modifier.fillMaxSize()) {
        Text(
            content,
            modifier = Modifier.weight(1f).verticalScroll(rememberScrollState()),
            style = MaterialTheme.typography.bodyLarge,
        )
        Row(
            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Button(onClick = onEdit, modifier = Modifier.weight(1f)) { Text("Edit") }
            OutlinedButton(
                onClick = { confirmDelete = true },
                modifier = Modifier.weight(1f),
            ) { Text("Delete") }
        }
    }

    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("Delete reflection?") },
            text = { Text("This permanently deletes your reflection. It can't be undone.") },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = false
                    onDelete()
                }) { Text("Delete") }
            },
            dismissButton = {
                TextButton(onClick = { confirmDelete = false }) { Text("Cancel") }
            },
        )
    }
}

@Composable
private fun EditState(
    initial: String,
    isNew: Boolean,
    onSave: (String) -> Unit,
    onCancel: () -> Unit,
) {
    var text by remember { mutableStateOf(initial) }

    Column(modifier = Modifier.fillMaxSize()) {
        OutlinedTextField(
            value = text,
            onValueChange = { text = it },
            label = { Text("Your private reflection") },
            modifier = Modifier.fillMaxWidth().weight(1f),
        )
        Row(
            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Button(onClick = { onSave(text) }, modifier = Modifier.weight(1f)) {
                Text(if (isNew) "Save" else "Update")
            }
            OutlinedButton(onClick = onCancel, modifier = Modifier.weight(1f)) {
                Text("Cancel")
            }
        }
    }
}
