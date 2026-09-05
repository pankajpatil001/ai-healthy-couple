# Healthy Couple — Android (Private Reflection slice)

Minimum Android client for the **Phase 2 Private Reflection** vertical slice.
This is intentionally **not** the full Healthy Couple app: it contains only what
is needed to prove the end-to-end product path

```
Android → Authentication → /api/v1 → Authorization → Encryption → PostgreSQL → back
```

## Scope

Included:
- Email/password sign-in and account creation (to obtain a session)
- Encrypted on-device session-token storage
- A small REST client for the `/api/v1` surface
- Private Reflection: create, view, edit, delete
- Loading / empty / error states
- A persistent privacy notice: a reflection is private to the user and is
  **not** automatically shared with their partner

Deliberately excluded: conversations, AI, safety, professionals, subscriptions,
relationship memory, dashboards, and any navigation beyond this feature. There
is no reflection *list* screen because the backend exposes no list endpoint.

## Structure

```
android/
├── settings.gradle.kts / build.gradle.kts / gradle.properties
└── app/
    ├── build.gradle.kts
    └── src/main/
        ├── AndroidManifest.xml
        ├── java/com/healthycouple/reflection/
        │   ├── MainActivity.kt            # two-destination navigation
        │   ├── data/                      # SessionStore, ReflectionApi, models
        │   └── ui/                        # AuthScreen, ReflectionScreen, ViewModels
        └── res/values/                    # strings, theme
```

## Running

### 1. Start the backend with the encryption key

Private Reflection content is encrypted at rest (AES-256-GCM). The backend
resolves the key from the `SecretsProvider`, so it must be present in the
environment before `uvicorn` starts — otherwise saving a reflection fails closed
with a 500 (by design; it never stores plaintext).

Generate a key once and put it in the repo-root `.env` (gitignored):

```bash
# from the project root
python -c "import os,base64; print('HC_SECRET_REFLECTION_ENCRYPTION_KEY_REFLECTION_V1=' + base64.urlsafe_b64encode(os.urandom(32)).decode())" >> .env
```

Then start the backend with that env loaded and bound to all interfaces:

```bash
set -a; source .env; set +a
.venv/bin/uvicorn app.main:app --host 0.0.0.0
```

> `.env` is **not** auto-loaded by the secrets provider (it reads `os.environ`
> directly), so you must `source` it — or export the var inline — before
> `uvicorn`. Never commit real key material; `.env` is gitignored.

### 2. Point the app at the backend (no source edits)

The API base URL is **not hardcoded**. It comes from the Gradle property
`apiBaseUrl`, defaulting to the Android emulator's host alias
`http://10.0.2.2:8000/api/v1`.

- **Emulator**: nothing to do — the default works.
- **Physical phone** (same Wi-Fi as your Mac): add one line to
  `android/local.properties` (gitignored) with your Mac's LAN IP from
  `ipconfig getifaddr en0`:

  ```properties
  apiBaseUrl=http://192.168.1.3:8000/api/v1
  ```

`API_BASE_URL` is compiled into `BuildConfig`, so re-sync/rebuild after changing it.

`API_BASE_URL` is compiled into `BuildConfig`, so re-sync/rebuild after changing it.

### 3. Run

Open the `android/` folder in Android Studio (Giraffe+), let it fetch the Gradle
wrapper, and run the `app` configuration.

> The Gradle wrapper JAR/binary is not committed; Android Studio (or
> `gradle wrapper`) will generate it on first open.
