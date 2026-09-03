package com.healthycouple.reflection.data

/** A private reflection as returned by the backend (decrypted content). */
data class Reflection(
    val id: String,
    val content: String,
    val coupleId: String?,
    val createdAt: String,
    val updatedAt: String,
)

/**
 * A small result wrapper for API calls so the UI can render success, a typed
 * error message, and (via the ViewModel) loading/empty states without leaking
 * transport details.
 */
sealed interface ApiResult<out T> {
    data class Ok<T>(val value: T) : ApiResult<T>
    data class Err(val code: String, val message: String) : ApiResult<Nothing>
}

/** Error codes the UI branches on (mirrors the backend's privacy-safe codes). */
object ErrorCodes {
    const val UNAUTHENTICATED = "UNAUTHENTICATED"
    const val AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    const val NOT_FOUND = "RESOURCE_NOT_FOUND"
    const val VALIDATION = "VALIDATION_ERROR"
    const val NETWORK = "NETWORK_ERROR"
    const val UNKNOWN = "UNKNOWN"
}
