#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
NATIVE_DIR="$PROJECT_DIR/.native"
SOURCE_DIR="$NATIVE_DIR/src/sing-box"
SDK_DIR="$NATIVE_DIR/android-sdk"
GO_ROOT="$NATIVE_DIR/go"
JDK_ROOT="$NATIVE_DIR/jdk17"
GO_ARCHIVE="$NATIVE_DIR/go1.25.5.linux-amd64.tar.gz"
JDK_ARCHIVE="$NATIVE_DIR/OpenJDK17U-jdk_x64_linux_hotspot_17.0.16_8.tar.gz"
NDK_ARCHIVE="$NATIVE_DIR/android-ndk-r28-linux.zip"
PLATFORM_ARCHIVE="$NATIVE_DIR/platform-35_r02.zip"
OUTPUT="$PROJECT_DIR/app/libs/libbox.aar"
SING_BOX_COMMIT="0b8995879f29a9b98ee027bc17b75e101445b238"
GO_SHA256="9e9b755d63b36acf30c12a9a3fc379243714c1c6d3dd72861da637f336ebb35b"
JDK_SHA256="166774efcf0f722f2ee18eba0039de2d685b350ee14d7b69e6f83437dafd2af1"
NDK_SHA256="a186b67e8810cb949514925e4f7a2255548fb55f5e9b0824a6430d012c1b695b"
PLATFORM_SHA256="0988cacad01b38a18a47bac14a0695f246bc76c1b06c0eeb8eb0dc825ab0c8e0"
LIBBOX_SHA256="bb7e98ea2f68507d0998cd61d60cba7fc45d98cb93b6d77f626846b4c54d30dc"

verify_file() {
  local expected="$1" file="$2" actual
  actual="$(sha256sum "$file" | cut -d ' ' -f 1)"
  if [ "$actual" != "$expected" ]; then
    echo "SHA-256 mismatch: $file" >&2
    echo "expected $expected" >&2
    echo "actual   $actual" >&2
    exit 1
  fi
}

mkdir -p "$NATIVE_DIR/src" "$PROJECT_DIR/app/libs" "$SDK_DIR/licenses" "$SDK_DIR/ndk"
printf '8933bad161af4178b1185d1a37fbf41ea5269c55\n' > "$SDK_DIR/licenses/android-sdk-license"

if [ ! -x "$GO_ROOT/bin/go" ]; then
  test -f "$GO_ARCHIVE" || curl -fL --retry 3 -o "$GO_ARCHIVE" https://go.dev/dl/go1.25.5.linux-amd64.tar.gz
  verify_file "$GO_SHA256" "$GO_ARCHIVE"
  rm -rf "$GO_ROOT"
  mkdir -p "$NATIVE_DIR/go-unpack"
  tar -xzf "$GO_ARCHIVE" -C "$NATIVE_DIR/go-unpack"
  mv "$NATIVE_DIR/go-unpack/go" "$GO_ROOT"
  rmdir "$NATIVE_DIR/go-unpack"
fi

if [ ! -x "$JDK_ROOT/bin/javac" ]; then
  test -f "$JDK_ARCHIVE" || curl -fL --retry 3 -o "$JDK_ARCHIVE" \
    https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.16%2B8/OpenJDK17U-jdk_x64_linux_hotspot_17.0.16_8.tar.gz
  verify_file "$JDK_SHA256" "$JDK_ARCHIVE"
  rm -rf "$JDK_ROOT" "$NATIVE_DIR/jdk-unpack"
  mkdir -p "$NATIVE_DIR/jdk-unpack"
  tar -xzf "$JDK_ARCHIVE" -C "$NATIVE_DIR/jdk-unpack"
  mv "$NATIVE_DIR/jdk-unpack"/* "$JDK_ROOT"
  rmdir "$NATIVE_DIR/jdk-unpack"
fi

if [ ! -f "$SDK_DIR/ndk/28.0.13004108/source.properties" ]; then
  test -f "$NDK_ARCHIVE" || curl -fL --retry 3 -o "$NDK_ARCHIVE" https://dl.google.com/android/repository/android-ndk-r28-linux.zip
  verify_file "$NDK_SHA256" "$NDK_ARCHIVE"
  unzip -q -o "$NDK_ARCHIVE" -d "$NATIVE_DIR/ndk-unpack"
  mv "$NATIVE_DIR/ndk-unpack/android-ndk-r28" "$SDK_DIR/ndk/28.0.13004108"
  rmdir "$NATIVE_DIR/ndk-unpack"
fi

if [ ! -f "$SDK_DIR/platforms/android-35/android.jar" ]; then
  test -f "$PLATFORM_ARCHIVE" || curl -fL --retry 3 -o "$PLATFORM_ARCHIVE" https://dl.google.com/android/repository/platform-35_r02.zip
  verify_file "$PLATFORM_SHA256" "$PLATFORM_ARCHIVE"
  mkdir -p "$SDK_DIR/platforms"
  unzip -q -o "$PLATFORM_ARCHIVE" -d "$SDK_DIR/platforms"
fi

if [ ! -d "$SOURCE_DIR/.git" ]; then
  git clone --filter=blob:none https://github.com/SagerNet/sing-box.git "$SOURCE_DIR"
fi
git -C "$SOURCE_DIR" fetch --depth=1 origin "$SING_BOX_COMMIT"
git -C "$SOURCE_DIR" checkout --detach "$SING_BOX_COMMIT"
git -C "$SOURCE_DIR" reset --hard "$SING_BOX_COMMIT"
git -C "$SOURCE_DIR" apply "$PROJECT_DIR/libbox-main-only.patch"
rm -rf "$SOURCE_DIR/build" "$SOURCE_DIR/libbox.aar" "$SOURCE_DIR/libbox-legacy.aar"

export PATH="$GO_ROOT/bin:$PATH"
export JAVA_HOME="$JDK_ROOT"
export PATH="$JAVA_HOME/bin:$PATH"
export GOPATH="$NATIVE_DIR/go-path"
export GOBIN="$GOPATH/bin"
export GOMODCACHE="$NATIVE_DIR/go-mod"
export GOCACHE="$NATIVE_DIR/go-cache"
export ANDROID_HOME="$SDK_DIR"
export ANDROID_NDK_HOME="$SDK_DIR/ndk/28.0.13004108"
mkdir -p "$GOBIN" "$GOPATH" "$GOMODCACHE" "$GOCACHE"

"$GO_ROOT/bin/go" install github.com/sagernet/gomobile/cmd/gomobile@v0.1.13
"$GO_ROOT/bin/go" install github.com/sagernet/gomobile/cmd/gobind@v0.1.13
(cd "$SOURCE_DIR" && PATH="$GOBIN:$PATH" "$GO_ROOT/bin/go" run ./cmd/internal/build_libbox -target android)
cp "$SOURCE_DIR/libbox.aar" "$OUTPUT"
verify_file "$LIBBOX_SHA256" "$OUTPUT"
(cd "$PROJECT_DIR/app/libs" && sha256sum libbox.aar > libbox.aar.sha256)
echo "libbox AAR: $OUTPUT"
