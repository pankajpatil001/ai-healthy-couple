package com.healthycouple.reflection.data

import com.healthycouple.reflection.BuildConfig
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * Minimal REST client for the Private Reflection slice.
 *
 * Talks to the backend `/api/v1` surface: authentication (register/login) and
 * reflection CRUD. It attaches the session token as a Bearer credential, parses
 * the `{"data": ...}` success envelope and the `{"error": {code, message}}`
 * failure envelope, and maps everything to [ApiResult] so the UI never sees raw
 * transport details.
 *
 * Deliberately small: no list endpoint (the backend has none), no features
 * beyond what this vertical slice requires.
 */
class ReflectionApi(
    private val session: SessionStore,
    private val baseUrl: String = BuildConfig.API_BASE_URL,
) {
    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    private val jsonMedia = "application/json; charset=utf-8".toMediaType()

    // -- auth -------------------------------------------------------------

    fun register(identifier: String, password: String): ApiResult<Unit> {
        val body = JSONObject()
            .put("auth_identifier", identifier)
            .put("credential_material", password)
        return when (val r = post("/auth/register", body, authed = false)) {
            is ApiResult.Ok -> ApiResult.Ok(Unit)
            is ApiResult.Err -> r
        }
    }

    /** Logs in and persists the returned session token. */
    fun login(identifier: String, password: String): ApiResult<Unit> {
        val body = JSONObject()
            .put("auth_identifier", identifier)
            .put("credential_material", password)
        return when (val r = post("/auth/login", body, authed = false)) {
            is ApiResult.Ok -> {
                val token = r.value.optString("session_token", "")
                if (token.isEmpty()) {
                    ApiResult.Err(ErrorCodes.UNKNOWN, "Login response was malformed.")
                } else {
                    session.sessionToken = token
                    ApiResult.Ok(Unit)
                }
            }
            is ApiResult.Err -> r
        }
    }

    fun logout() {
        // Best-effort server-side revoke; local token cleared regardless.
        session.sessionToken?.let {
            runCatching { post("/auth/logout", JSONObject(), authed = true) }
        }
        session.clear()
    }

    // -- reflections ------------------------------------------------------

    fun create(content: String, coupleId: String? = null): ApiResult<Reflection> {
        val body = JSONObject().put("content", content)
        if (coupleId != null) body.put("couple_id", coupleId)
        return post("/reflections", body, authed = true).map { it.toReflection() }
    }

    fun get(id: String): ApiResult<Reflection> =
        get("/reflections/$id").map { it.toReflection() }

    fun update(id: String, content: String): ApiResult<Reflection> {
        val body = JSONObject().put("content", content)
        return patch("/reflections/$id", body).map { it.toReflection() }
    }

    fun delete(id: String): ApiResult<Unit> =
        delete("/reflections/$id").map { }

    // -- HTTP plumbing ----------------------------------------------------

    private fun post(path: String, body: JSONObject, authed: Boolean) =
        execute(requestBuilder(path, authed).post(body.toString().toRequestBody(jsonMedia)).build())

    private fun patch(path: String, body: JSONObject) =
        execute(requestBuilder(path, true).patch(body.toString().toRequestBody(jsonMedia)).build())

    private fun get(path: String) =
        execute(requestBuilder(path, true).get().build())

    private fun delete(path: String) =
        execute(requestBuilder(path, true).delete().build())

    private fun requestBuilder(path: String, authed: Boolean): Request.Builder {
        val b = Request.Builder().url(baseUrl + path)
        if (authed) {
            session.sessionToken?.let { b.header("Authorization", "Bearer $it") }
        }
        return b
    }

    /** Execute a request and reduce it to an [ApiResult] over the `data` object. */
    private fun execute(request: Request): ApiResult<JSONObject> {
        return try {
            client.newCall(request).execute().use { resp ->
                val text = resp.body?.string().orEmpty()
                val json = if (text.isBlank()) JSONObject() else JSONObject(text)
                if (resp.isSuccessful) {
                    ApiResult.Ok(json.optJSONObject("data") ?: JSONObject())
                } else {
                    val err = json.optJSONObject("error")
                    val code = err?.optString("code") ?: ErrorCodes.UNKNOWN
                    val message = err?.optString("message") ?: "Request failed."
                    ApiResult.Err(code, message)
                }
            }
        } catch (e: IOException) {
            ApiResult.Err(ErrorCodes.NETWORK, "Network error. Please try again.")
        } catch (e: Exception) {
            ApiResult.Err(ErrorCodes.UNKNOWN, "Something went wrong.")
        }
    }
}

private fun <T> ApiResult<JSONObject>.map(transform: (JSONObject) -> T): ApiResult<T> =
    when (this) {
        is ApiResult.Ok -> ApiResult.Ok(transform(value))
        is ApiResult.Err -> this
    }

private fun JSONObject.toReflection(): Reflection = Reflection(
    id = optString("id"),
    content = optString("content"),
    coupleId = if (isNull("couple_id")) null else optString("couple_id"),
    createdAt = optString("created_at"),
    updatedAt = optString("updated_at"),
)
