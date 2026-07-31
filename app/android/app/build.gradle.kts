plugins {
    id("com.android.application")
    id("kotlin-android")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    // `flutter create` derives this from the project name, giving
    // `com.liostunnel.liostunnel_app`. Normalised to `com.liostunnel.app`
    // because JNI escapes an underscore in a package segment to `_1`, so the
    // generated name would make every native symbol read
    // `Java_com_liostunnel_liostunnel_1app_...`. The JNI function names in
    // `platform/android` depend on this value.
    namespace = "com.liostunnel.app"
    compileSdk = 34
    ndkVersion = "27.1.12297006"

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_17.toString()
    }

    defaultConfig {
        applicationId = "com.liostunnel.app"
        // Pinned rather than inherited from `flutter.*`: the VpnService work
        // targets a known API surface, and a Flutter upgrade silently moving
        // either of these would change which foreground-service rules apply.
        minSdk = 29
        targetSdk = 34
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    buildTypes {
        release {
            // TODO: Add your own signing config for the release build.
            // Signing with the debug keys for now, so `flutter run --release` works.
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}

flutter {
    source = "../.."
}
