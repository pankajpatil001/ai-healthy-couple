plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.healthycouple.reflection"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.healthycouple.reflection"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"

        // Backend base URL for the Private Reflection slice. Points at the
        // /api/v1 surface. Override per build type / local run as needed. The
        // Android emulator reaches the host machine at 10.0.2.2.
        buildConfigField("String", "API_BASE_URL", "\"http://10.0.2.2:8000/api/v1\"")
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
