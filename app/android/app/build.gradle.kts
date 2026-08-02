plugins {
    id("com.android.application")
    id("kotlin-android")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    // The app's identity, and load-bearing beyond that: JNI derives every
    // native symbol name from it, so `platform/android` must be renamed in
    // step with this line or the service throws UnsatisfiedLinkError on
    // start. `testing/verify-jni-symbols.sh` is what checks the two agree.
    //
    // No underscores here on purpose. JNI escapes one in a package segment to
    // `_1`, which is what `flutter create`'s derived
    // `com.liostunnel.liostunnel_app` would have produced.
    namespace = "id.liostech.liostunnel"
    compileSdk = 36
    ndkVersion = "27.1.12297006"

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_17.toString()
    }

    defaultConfig {
        applicationId = "id.liostech.liostunnel"
        // Pinned rather than inherited from `flutter.*`: the VpnService work
        // targets a known API surface, and a Flutter upgrade silently moving
        // either of these would change which foreground-service rules apply.
        minSdk = 29
        // 36, not 34. Google Play requires new apps and updates to target
        // Android 16 from 31 August 2026; an app on 34 cannot be submitted
        // after that and is only served to devices running 34 or older.
        //
        // This crossed two releases that both tightened what this app depends
        // on -- foreground service types in 15, and 15's 16 KB native page
        // size, which matters here because we ship .so files. Neither is
        // theoretical for a VpnService with a Rust engine behind it.
        targetSdk = 36
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
