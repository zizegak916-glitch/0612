#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOLCHAIN_DIR="${IP_BATCH_TOOLCHAIN_DIR:-$PROJECT_DIR/.toolchain}"
PLATFORM_DIR="$TOOLCHAIN_DIR/platform"
BUILD_TOOLS_DIR="$TOOLCHAIN_DIR/build-tools"
BUILD_DIR="$PROJECT_DIR/build"
ECJ_JAR="$TOOLCHAIN_DIR/ecj-3.37.0.jar"

mkdir -p "$PLATFORM_DIR" "$BUILD_TOOLS_DIR" "$BUILD_DIR/downloads"

if ! find "$PLATFORM_DIR" -name android.jar -type f -print -quit | grep -q .; then
  PLATFORM_ZIP="$BUILD_DIR/downloads/platform-35.zip"
  test -f "$PLATFORM_ZIP" || curl -fL --retry 2 -o "$PLATFORM_ZIP" \
    https://dl.google.com/android/repository/platform-35_r02.zip
  unzip -q -o "$PLATFORM_ZIP" -d "$PLATFORM_DIR"
fi

if ! find "$BUILD_TOOLS_DIR" -name aapt2 -type f -print -quit | grep -q .; then
  TOOLS_ZIP="$BUILD_DIR/downloads/build-tools-35.zip"
  test -f "$TOOLS_ZIP" || curl -fL --retry 2 -o "$TOOLS_ZIP" \
    https://dl.google.com/android/repository/build-tools_r35_linux.zip
  unzip -q -o "$TOOLS_ZIP" -d "$BUILD_TOOLS_DIR"
fi

if [ ! -f "$ECJ_JAR" ]; then
  curl -fL --retry 2 -o "$ECJ_JAR" \
    https://repo1.maven.org/maven2/org/eclipse/jdt/ecj/3.37.0/ecj-3.37.0.jar
fi

ANDROID_JAR="$(find "$PLATFORM_DIR" -name android.jar -type f -print -quit)"
AAPT2="$(find "$BUILD_TOOLS_DIR" -name aapt2 -type f -print -quit)"
D8="$(find "$BUILD_TOOLS_DIR" -name d8 -type f -print -quit)"
ZIPALIGN="$(find "$BUILD_TOOLS_DIR" -name zipalign -type f -print -quit)"
APKSIGNER="$(find "$BUILD_TOOLS_DIR" -name apksigner -type f -print -quit)"

chmod +x "$AAPT2" "$D8" "$ZIPALIGN" "$APKSIGNER"
rm -rf "$BUILD_DIR/gen" "$BUILD_DIR/classes" "$BUILD_DIR/test-classes" "$BUILD_DIR/dex" \
  "$BUILD_DIR/compiled.zip" "$BUILD_DIR/classes.jar"
mkdir -p "$BUILD_DIR/gen" "$BUILD_DIR/classes" "$BUILD_DIR/test-classes" "$BUILD_DIR/dex"

"$AAPT2" compile --dir "$PROJECT_DIR/app/src/main/res" -o "$BUILD_DIR/compiled.zip"
"$AAPT2" link \
  -o "$BUILD_DIR/base.apk" \
  -I "$ANDROID_JAR" \
  --manifest "$PROJECT_DIR/app/src/main/AndroidManifest.xml" \
  --java "$BUILD_DIR/gen" \
  --min-sdk-version 23 \
  --target-sdk-version 35 \
  --version-code 5 \
  --version-name 4.0.0 \
  "$BUILD_DIR/compiled.zip"

find "$PROJECT_DIR/app/src/main/java" "$BUILD_DIR/gen" -name '*.java' -print > "$BUILD_DIR/sources.list"
java -jar "$ECJ_JAR" -8 -encoding UTF-8 -classpath "$ANDROID_JAR" \
  -d "$BUILD_DIR/classes" @"$BUILD_DIR/sources.list"
java -jar "$ECJ_JAR" -8 -encoding UTF-8 -classpath "$BUILD_DIR/classes" \
  -d "$BUILD_DIR/test-classes" "$PROJECT_DIR/tests/ParserSmokeTest.java"
java -cp "$BUILD_DIR/classes:$BUILD_DIR/test-classes" com.fool.ipbatch.ParserSmokeTest
java --add-modules jdk.httpserver -cp "$BUILD_DIR/classes" "$PROJECT_DIR/tests/DownloaderSmokeTest.java"
(cd "$BUILD_DIR/classes" && zip -q -r "$BUILD_DIR/classes.jar" .)
"$D8" --min-api 23 --lib "$ANDROID_JAR" --output "$BUILD_DIR/dex" "$BUILD_DIR/classes.jar"

cp "$BUILD_DIR/base.apk" "$BUILD_DIR/unsigned.apk"
(cd "$BUILD_DIR/dex" && zip -q -j "$BUILD_DIR/unsigned.apk" classes*.dex)
"$ZIPALIGN" -p -f 4 "$BUILD_DIR/unsigned.apk" "$BUILD_DIR/aligned.apk"

KEYSTORE="$BUILD_DIR/debug.keystore"
if [ ! -f "$KEYSTORE" ]; then
  keytool -genkeypair -keystore "$KEYSTORE" -storepass android -keypass android \
    -alias androiddebugkey -dname "CN=IP Batch Inspector Debug,O=Local Build,C=CN" \
    -keyalg RSA -keysize 2048 -validity 10000 >/dev/null 2>&1
fi

"$APKSIGNER" sign --ks "$KEYSTORE" --ks-pass pass:android --key-pass pass:android \
  --out "$BUILD_DIR/IPBatchInspector-v4.0.0-android.apk" "$BUILD_DIR/aligned.apk"
"$APKSIGNER" verify --verbose "$BUILD_DIR/IPBatchInspector-v4.0.0-android.apk"

echo "APK: $BUILD_DIR/IPBatchInspector-v4.0.0-android.apk"
