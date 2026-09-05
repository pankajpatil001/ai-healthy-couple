import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Machine-specific overrides live in android/local.properties (gitignored).
// This makes `apiBaseUrl` there behave like a Gradle property, so developers can
// point the app at their own backend without touching any tracked file.
val localProperties = Properties().apply {
    val f = rootProject.file("local.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

fun resolveApiBaseUrl(): String =
    (project.findProperty("apiBaseUrl") as String?)
        ?: localProperties.getProperty("apiBaseUrl")
        ?: "http://192.168.1.3:8000/api/v1"

android {
    namespace = "com.healthycouple.reflection"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.healthycouple.reflection"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"

        // Backend base URL for the Private Reflection slice (/api/v1 surface).
        //
        // No host is hardcoded in source. The value comes from the Gradle
        // property `apiBaseUrl`, defaulting to the Android emulator's host alias
        // (10.0.2.2 -> the machine running uvicorn). Override it WITHOUT editing
        // this tracked file, e.g.:
        //   * per-developer: add `apiBaseUrl=http://192.168.1.3:8000/api/v1` to
        //     ~/.gradle/gradle.properties or android/local.properties
        //   * one-off build: ./gradlew :app:assembleDebug -PapiBaseUrl=...
        // A physical phone needs the Mac's LAN IP (same Wi-Fi); the emulator uses
        // the 10.0.2.2 default.
        buildConfigField("String", "API_BASE_URL", "\"${resolveApiBaseUrl()}\"")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.14"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.06.00")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.3")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.3")
    // Provides androidx.lifecycle.compose.collectAsStateWithLifecycle.
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.3")
    implementation("androidx.activity:activity-compose:1.9.0")

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-core")

    // Networking: OkHttp for the small REST client; JSON parsing via org.json
    // (bundled with Android) to avoid extra serialization dependencies for this
    // minimal slice.
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // Encrypted at-rest storage for the session token on-device.
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
}
