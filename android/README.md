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

1. Start the backend (`uvicorn app.main:app`) on the host machine.
2. The app targets `http://10.0.2.2:8000/api/v1` by default (the Android
   emulator's alias for the host). Override `API_BASE_URL` in
   `app/build.gradle.kts` for a device or a different host/port.
3. Open the `android/` folder in Android Studio (Giraffe+), let it fetch the
   Gradle wrapper, and run the `app` configuration on an emulator.

> The Gradle wrapper JAR/binary is not committed; Android Studio (or
> `gradle wrapper`) will generate it on first open.
