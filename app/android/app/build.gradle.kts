import java.util.Properties

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

    // The upload key, read from a file that is never committed.
    //
    // `android/key.properties` holds the keystore path and its passwords. It
    // is git-ignored, and so is the keystore itself: an upload key in the
    // repository is an upload key in every clone and every CI log.
    //
    // Absent, the release build falls back to debug signing so that CI and
    // `flutter run --release` keep working. That fallback is deliberately
    // LOUD, and `testing/verify-apk.sh` refuses to call a debug-signed
    // artifact publishable -- a debug-signed bundle is rejected by Play, and
    // finding that out at upload time is a wasted trip.
    val keyProps = Properties()
    val keyPropsFile = rootProject.file("key.properties")
    val hasUploadKey = keyPropsFile.exists()
    if (hasUploadKey) {
        keyPropsFile.inputStream().use { keyProps.load(it) }
    } else {
        logger.warn("key.properties absent: release builds will be DEBUG-SIGNED and cannot be uploaded to Play. See docs/ANDROID-RELEASE.md")
    }

    signingConfigs {
        if (hasUploadKey) {
            create("upload") {
                storeFile = file(keyProps.getProperty("storeFile"))
                storePassword = keyProps.getProperty("storePassword")
                keyAlias = keyProps.getProperty("keyAlias")
                keyPassword = keyProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            signingConfig = if (hasUploadKey) {
                signingConfigs.getByName("upload")
            } else {
                signingConfigs.getByName("debug")
            }
        }
    }
}

flutter {
    source = "../.."
}
