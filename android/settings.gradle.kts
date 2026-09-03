// Minimum Android project for the Phase 2 Private Reflection vertical slice.
// Scope is deliberately limited to authentication/session + Private Reflection
// CRUD against the /api/v1 backend. It is NOT the full Healthy Couple app.

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "HealthyCoupleReflection"
include(":app")
