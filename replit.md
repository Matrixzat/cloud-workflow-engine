# Dex2c Mega (com.ultra.dex2cvmp)

A Native Android app that protects APKs by converting DEX bytecode to native C/C++ code using the Dex2c technique.

## Stack
- **Language:** Java + C/C++ (NDK)
- **Build system:** Gradle (AGP 8.3.2)
- **NDK version:** 25.2.9519653
- **Min SDK:** 26 | **Target SDK:** 28
- **Signing:** `Reveral_X_Mods.jks` (credentials via `gradle.properties` / `local.properties`)

## Project structure
- `src/main/java/com/ultra/` — Java source
- `src/main/cpp/` — Native C/C++ source
- `src/main/jniLibs/` — Prebuilt `.so` libraries
- `stub-loader/` — Sub-module; its compiled DEX is extracted into `src/main/assets/stub.dex` before the main build
- `workflow/` — GitHub Actions CI workflows (not for Replit)

## Building
This is an Android project and cannot be run or previewed on Replit directly (no Android emulator).

To build an APK on a machine with the Android SDK:
```bash
./gradlew :stub-loader:assembleRelease   # build stub-loader first
./gradlew assembleRelease                # build the main APK
```

Signing credentials (`signing.storePassword`, `signing.keyPassword`, `signing.keyAlias`) must be set in `gradle.properties` or `local.properties`.

The CI build is automated via GitHub Actions (`workflow/build.yml`).

## User preferences
