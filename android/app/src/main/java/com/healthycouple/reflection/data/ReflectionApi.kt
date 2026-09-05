package com.healthycouple.reflection.data

import com.healthycouple.reflection.BuildConfig
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * Minimal REST client for the Private Reflection slice.
 *
 * Talks to the backend `/api/v1` surface: authentication (register/login) and
 * reflection list + CRUD. It attaches the session token as a Bearer credential,
 * parses the `{"data": ...}` success envelope and the `{"error": {code, message}}`
 * failure envelope, and maps everything to [ApiResult] so the UI never sees raw
 * transport details.
 *
 * Session expiry is handled centrally: whenever an authenticated request comes
 * back `401 UNAUTHENTICATED`, the local session is cleared and [onSessionExpired]
 * is invoked so the app can return the user to the login screen. Callers still
 * receive the `ApiResult.Err` so they can surface a message.
 */
class ReflectionApi(
    private val session: SessionStore,
    private val baseUrl: String = BuildConfig.API_BASE_URL,
    /** Invoked once when an authed call is rejected with 401 (session expired). */
    var onSessionExpired: (() -> Unit)? = null,
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
        return when (val r = httpPost("/auth/register", body, authed = false)) {
            is ApiResult.Ok -> ApiResult.Ok(Unit)
            is ApiResult.Err -> r
        }
    }

    /** Logs in and persists the returned session token. */
    fun login(identifier: String, password: String): ApiResult<Unit> {
        val body = JSONObject()
            .put("auth_identifier", identifier)
            .put("credential_material", password)
        return when (val r = httpPost("/auth/login", body, authed = false)) {
            is ApiResult.Ok -> {
                val token = (r.value as? JSONObject)?.optString("session_token", "").orEmpty()
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
            runCatching { httpPost("/auth/logout", JSONObject(), authed = true) }
        }
        session.clear()
    }

    // -- reflections ------------------------------------------------------

    /** List the caller's own reflections as content-free summaries. */
    fun list(): ApiResult<List<ReflectionSummary>> =
        when (val r = httpGet("/reflections")) {
            is ApiResult.Ok -> {
                val arr = r.value as? JSONArray ?: JSONArray()
                val out = ArrayList<ReflectionSummary>(arr.length())
                for (i in 0 until arr.length()) out.add(arr.getJSONObject(i).toSummary())
                ApiResult.Ok(out)
            }
            is ApiResult.Err -> r
        }

    fun create(content: String, coupleId: String? = null): ApiResult<Reflection> {
        val body = JSONObject().put("content", content)
        if (coupleId != null) body.put("couple_id", coupleId)
        return httpPost("/reflections", body, authed = true).mapObject { it.toReflection() }
    }

    fun get(id: String): ApiResult<Reflection> =
        httpGet("/reflections/$id").mapObject { it.toReflection() }

    fun update(id: String, content: String): ApiResult<Reflection> {
        val body = JSONObject().put("content", content)
        return httpPatch("/reflections/$id", body).mapObject { it.toReflection() }
    }

    fun delete(id: String): ApiResult<Unit> =
        httpDelete("/reflections/$id").mapObject { }

    // -- HTTP plumbing ----------------------------------------------------

    private fun httpPost(path: String, body: JSONObject, authed: Boolean) =
        execute(requestBuilder(path, authed).post(body.toString().toRequestBody(jsonMedia)).build())

    private fun httpPatch(path: String, body: JSONObject) =
        execute(requestBuilder(path, true).patch(body.toString().toRequestBody(jsonMedia)).build())

    private fun httpGet(path: String) =
        execute(requestBuilder(path, true).get().build())

    private fun httpDelete(path: String) =
        execute(requestBuilder(path, true).delete().build())

    private fun requestBuilder(path: String, authed: Boolean): Request.Builder {
        val b = Request.Builder().url(baseUrl + path)
        if (authed) {
            session.sessionToken?.let { b.header("Authorization", "Bearer $it") }
        }
        return b
    }

    /**
     * Execute a request and reduce it to an [ApiResult] over the `data` value,
     * which may be a JSON object or a JSON array.
     *
     * On `401 UNAUTHENTICATED` the local session is cleared and
     * [onSessionExpired] is fired so the app can bounce to login; the error is
     * still returned to the caller with a session-expired message.
     */
    private fun execute(request: Request): ApiResult<Any> {
        return try {
            client.newCall(request).execute().use { resp ->
                val text = resp.body?.string().orEmpty()
                if (resp.isSuccessful) {
                    // `data` may be a JSON object (single reflection) or a JSON
                    // array (list); callers extract the shape they expect.
                    val root = if (text.isBlank()) JSONObject() else JSONObject(text)
                    val data: Any = root.opt("data") ?: JSONObject()
                    ApiResult.Ok(data)
                } else {
                    val root = if (text.isBlank()) JSONObject() else JSONObject(text)
                    val err = root.optJSONObject("error")
                    val code = err?.optString("code") ?: ErrorCodes.UNKNOWN
                    if (resp.code == 401 || code == ErrorCodes.UNAUTHENTICATED) {
                        // Central session-expiry handling.
                        session.clear()
                        onSessionExpired?.invoke()
                        ApiResult.Err(
                            ErrorCodes.UNAUTHENTICATED,
                            "Your session has expired. Please log in again.",
                        )
                    } else {
                        val message = err?.optString("message") ?: "Request failed."
                        ApiResult.Err(code, message)
                    }
                }
            }
        } catch (e: IOException) {
            ApiResult.Err(ErrorCodes.NETWORK, "Network error. Please try again.")
        } catch (e: Exception) {
            ApiResult.Err(ErrorCodes.UNKNOWN, "Something went wrong.")
        }
    }
}

/** Map a success whose `data` is a JSON object into a typed value. */
private fun <T> ApiResult<Any>.mapObject(transform: (JSONObject) -> T): ApiResult<T> =
    when (this) {
        is ApiResult.Ok -> ApiResult.Ok(transform(value as? JSONObject ?: JSONObject()))
        is ApiResult.Err -> this
    }

private fun JSONObject.toReflection(): Reflection = Reflection(
    id = optString("id"),
    content = optString("content"),
    coupleId = if (isNull("couple_id")) null else optString("couple_id"),
    createdAt = optString("created_at"),
    updatedAt = optString("updated_at"),
)

private fun JSONObject.toSummary(): ReflectionSummary = ReflectionSummary(
    id = optString("id"),
    coupleId = if (isNull("couple_id")) null else optString("couple_id"),
    createdAt = optString("created_at"),
    updatedAt = optString("updated_at"),
)
