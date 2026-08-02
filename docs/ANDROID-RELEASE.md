# Releasing the Android app

Everything here that touches a key or a Google account is yours. This file
exists so none of it has to be worked out at upload time.

## 1. Create the upload key

Once, ever. Run it yourself: the key is your identity as the publisher, and it
should not pass through anyone else's hands.

```bash
keytool -genkey -v \
  -keystore ~/liostunnel-upload.jks \
  -keyalg RSA -keysize 4096 -validity 10000 \
  -alias upload
```

**Keep the keystore and its passwords backed up somewhere you would still have
after losing this machine.** With Play App Signing an *upload* key can be reset
by Google if you lose it, so this is recoverable — but the reset takes days and
happens at the worst possible moment.

Store it outside the repository. `**/*.jks` and `key.properties` are
git-ignored, but the only file that cannot leak is the one that was never
there.

## 2. Point the build at it

Create `app/android/key.properties` — git-ignored, never committed:

```properties
storeFile=/Users/you/liostunnel-upload.jks
storePassword=…
keyAlias=upload
keyPassword=…
```

Without this file the release build still works, but **falls back to debug
signing** so that CI and `flutter run --release` keep going. Gradle warns when
it does, and `testing/verify-aab.sh` refuses to call the result publishable —
Play rejects a debug-signed bundle, and finding that out at upload is a wasted
trip.

## 3. Build and check the bundle

```bash
cd app
flutter build appbundle --release
../testing/verify-aab.sh build/app/outputs/bundle/release/app-release.aab
```

The verifier checks the four things that are silent failures otherwise: that it
is a bundle at all, that the Rust engine is present for every ABI, that it is
signed with a real key rather than the debug one, and that the native libraries
are **16 KB page aligned** — Android 15 devices cannot map a 4 KB-aligned
library, so the app would install and then fail to load its own engine.

CI does not build the bundle, because CI has no key. It builds and verifies the
per-ABI APKs instead. If you later want CI to produce the upload artifact, add
the keystore as a base64 repository secret and write it out in the job.

## 4. Play Console

These are yours; none of them can be automated from here.

- **Register as a developer** — one-off fee, plus identity verification, which
  now takes days rather than minutes.
- **Complete the VpnService declaration.** Any app using `VpnService` must
  submit it. Not submitting is itself a policy violation, independent of what
  the app does.
- **Privacy policy URL** — see `docs/PRIVACY.md`, which describes what this app
  actually does. Host it somewhere public and paste the URL.
- **Data safety form** — the answers follow from the privacy policy.
- **Target API level.** New apps and updates must target **API 36 from 31
  August 2026**. `app/android/app/build.gradle.kts` is on 36.

### Worth doing, not required

VPN apps get more scrutiny than most, and deservedly: the category is full of
apps that route traffic somewhere the user did not expect. Google runs an
**Independent Security Review (MASA)** whose badge appears in the Data safety
section. It costs money and time with a third-party lab, and it is the
difference between looking like a VPN client and looking like the other
thousand.

## 5. What ships, and what it weighs

`--split-per-abi` for direct distribution, a bundle for Play. Play splits the
bundle per device itself, so the ~60 MB bundle delivers about 24 MB to an
arm64 phone.

Never a universal APK: it carries every architecture for no benefit on any
single device.
