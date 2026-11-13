$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$sdk = $env:ANDROID_SDK_ROOT
if (!$sdk) { $sdk = $env:ANDROID_HOME }
if (!$sdk) { $sdk = Join-Path $env:LOCALAPPDATA 'Android/Sdk' }
$ndk = Get-ChildItem -LiteralPath (Join-Path $sdk 'ndk') -Directory | Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
if (!$ndk) { throw 'Install the Android NDK' }
$bin = Join-Path $ndk.FullName 'toolchains/llvm/prebuilt/windows-x86_64/bin'
$go = (Get-Command go.exe -ErrorAction SilentlyContinue).Source
if (!$go) { $go = Join-Path $env:USERPROFILE 'dev-tools/go/bin/go.exe' }
$env:CGO_ENABLED = '1'
$env:GOOS = 'android'
Push-Location (Join-Path $root 'core')
try {
    foreach ($target in @(
        @{ Arch = 'arm64'; ABI = 'arm64-v8a'; Triple = 'aarch64-linux-android'; API = 24 }
        @{ Arch = 'arm'; ABI = 'armeabi-v7a'; Triple = 'armv7a-linux-androideabi'; API = 21 }
    )) {
        $env:GOARCH = $target.Arch
        $env:GOARM = '7'
        $env:CC = '"' + (Join-Path $bin 'clang.exe') + '" --target=' + $target.Triple + $target.API
        $dir = Join-Path $root "app/src/keelbismark/jniLibs/$($target.ABI)"
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        & $go build -trimpath -buildmode=pie -ldflags '-s -w -extldflags=-Wl,-z,max-page-size=16384' -o (Join-Path $dir 'libtgproxy.so') ./cmd/proxy
        if ($LASTEXITCODE -ne 0) { throw "Build failed for $($target.ABI)" }
    }
} finally {
    Pop-Location
}
