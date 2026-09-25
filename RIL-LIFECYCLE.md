# Tahap 6 — integrasi lifecycle di repository library

Implementasi ini hanya mengubah NexilisZTA di NexilisLibraryiOS. Repository OneApp, startup
host contoh, konfigurasi production dan API bisnis NexilisLite tidak diubah. Default RIL tetap off.

## Konfigurasi sebelum startup

Bangun `RILConfiguration` dari konfigurasi deployment tepercaya seperti pada RIL-CLIENT.md.
Set appID (Team ID + Bundle ID), bundleID, tenant, environment App Attest, origin HTTPS,
challengeURL dan enrollmentURL secara eksplisit. Jangan menebak environment dari Debug/Release.
Challenge URL wajib sama dengan challengeEndpoint ZTA. Endpoint pilot wajib cocok origin dan
path publik final, termasuk prefix proxy. Pinning tetap mengikuti konfigurasi ZTA existing.

```swift
// ztaConfiguration dan rilConfiguration telah diisi konfigurasi deployment sebenarnya.
var configuration = ztaConfiguration
configuration.ril = rilConfiguration
APISZTA.configure(configuration, onFailure: { error in
    // Tampilkan kegagalan bootstrap ZTA.
}, onReady: {
    // Sesi bisnis ZTA siap. Ini BUKAN pemberitahuan enrollment RIL selesai.
})
```

Alternatif jalur NexilisLite: berikan configuration yang sama ke
`APIS.configureSentinel(configuration)` sebelum `APIS.connect(...)` pertama. Jangan memasang
RIL sesudah sesi bisnis sudah berjalan karena fast path authorization existing dapat melewati
configure. Jalur manual yang hanya memakai `applyConfiguration` harus lebih dulu memanggil
`try APISZTA.installRILLifecycle(for: configuration)` pada MainActor; setelah otorisasi selesai,
panggil `try await APISZTA.rilSession?.sessionAuthorized()` sebelum polling.

Managed lifecycle dan instalasi manual `installRILPilotTransport` tahap 5 adalah alternatif,
bukan dipakai bersamaan. Konfigurasi managed berulang yang sama idempotent; mengganti scope,
endpoint/policy atau mengubah ril menjadi nil setelah managed terpasang ditolak tanpa downgrade.

## Urutan dan state

1. Adapter dipasang sebelum chain ZTA mulai. Selama belum ready, pilot gagal lokal, bukan unsigned.
2. Bootstrap/App Attest/key delivery berjalan dengan proteksi existing, tanpa RIL.
3. Setelah ada token ZTA hidup, managed session menjalankan enrollment. Pemanggilan bersamaan
   berbagi satu operasi. Candidate recovery tetap ditangani RILClient tahap 4.
4. Bila berhasil, telemetry loop dimulai dan security-pack pertama diminta dengan signature.
   Polling status existing boleh tetap berjalan; request pilot sebelum ready tetap ditolak.
5. Offline regular/tanpa token tidak dipaksa enrollment. Kesiapan bisnis dan kesiapan RIL terpisah.

`APISZTA.rilSession` diakses pada MainActor. `state` bernilai waitingForSession, enrolling,
ready, failed atau suspended. `lastError` menyimpan kegagalan terakhir tanpa logging credential.
Notification `io.nexilis.ril.stateChanged` dikirim pada main thread dengan userInfo `state`.
Host harus membaca state awal juga, bukan hanya menunggu notification. Jangan mengganti
onStateChange pada session managed jika masih membutuhkan notification bawaan.
State ready adalah kesiapan lokal, bukan bukti kunci belum dicabut di registry server.

## Recovery dan rotasi

- Kegagalan enrollment/signing menutup gate; tidak menghapus kunci atau retry tanpa batas.
- Setelah jaringan/sesi pulih, panggil `try await APISZTA.retryRILEnrollment()` secara eksplisit.
  Ini tidak mereset App Attest dan tidak menciptakan candidate baru jika candidate sudah tersimpan.
- Rotasi eksplisit melalui `try await APISZTA.rilSession?.rotateKey()`. Selama rotasi, signing
  ditahan. Timeout diteruskan sebagai failed; retryEnrollment melanjutkan recovery tahap 4.
- Respons RIL_REQUIRED, KEY_UNAVAILABLE, BINDING_MISMATCH, PROFILE_UNSUPPORTED,
  INVALID_SIGNATURE, DIGEST_MISMATCH, EXPIRED dan CLOCK_SKEW dari token yang masih sama
  mengubah session ready menjadi failed. Tidak otomatis clear registration/Keychain.
- KEY_UNAVAILABLE tidak otomatis diatasi oleh fast path enroll pada active key. Host harus
  menentukan apakah rotasi, revocation, atau enrollment ulang memang diizinkan backend.
  Tidak ada jaminan retry lokal akan memulihkan kunci yang dicabut server.
- Telemetry tetap mengikuti latch tahap 5: non-2xx/hasil ambigu ditahan. Enrollment berhasil
  TIDAK membuka latch ini. Rekonsiliasi hasil/deduplikasi atau keputusan eksplisit membuang
  pending buffer harus mendahului resumeRILTelemetryAfterReconciliation().
- Tidak ada koordinasi global counter App Attest lintas semua flow existing; uji concurrent
  assertion pada perangkat tetap wajib. Tidak ada koreksi jam otomatis.

## Revocation, logout, hard wipe

Revocation ZTA menghentikan telemetry, membuang otorisasi existing, dan men-suspend RIL; kunci
dipertahankan untuk recovery eksplisit. Retry bootstrap yang mereset registration juga
men-suspend session; mismatch identitas lama/baru tidak diatasi dengan menghapus kunci diam-diam.

Host logout yang memang mengakhiri otorisasi instalasi:

```swift
APISZTA.revokeLocalAuthorization(reason: "host logout")
try await APISZTA.clearRILLocalKeys()
```

clearRILLocalKeys adalah penghapusan lokal, bukan endpoint revocation registry RIL. Jangan
memanggilnya untuk timeout atau setiap 403. Keputusan mengikat logout akun bisnis dengan
revocation instalasi tetap milik host; library tidak mengubah logout NexilisLite secara global.

Notification hard wipe existing otomatis memicu clearLocalKeys pada managed session. Token
ditutup oleh SecureWipe existing terlebih dahulu. Penghapusan menunggu enrollment/rotasi yang
sudah dimulai selesai/dibatalkan sebelum menghapus Keychain, agar late completion tidak menulis
kunci kembali. Gate tetap tertutup selama proses tersebut. Penghapusan gagal tidak dilaporkan
berhasil; state tetap suspended dan lastError tersedia, retry penghapusan harus eksplisit.
Hanya scope managed saat ini yang dibersihkan, bukan enumerasi semua scope historis/keychain.

## Verifikasi

Test core/adapter/backend tetap memakai perintah RIL-CLIENT.md. Tambahan lifecycle:

```sh
ril_build_dir=$(mktemp -d /private/tmp/ril-lifecycle-tests.XXXXXX)
xcrun swiftc -swift-version 5 -module-cache-path "$ril_build_dir/cache" \
  NexilisZTA/Source/NXLogger.swift NexilisZTA/Source/RIL/RILCore.swift NexilisZTA/Source/RIL/RILKeyStore.swift \
  NexilisZTA/Source/RIL/RILClient.swift NexilisZTA/Source/RIL/RILSession.swift \
  Tests/RIL/RILSessionTests.swift -o "$ril_build_dir/session-tests"
"$ril_build_dir/session-tests"
```

31 pemeriksaan lifecycle (termasuk request yang tidak bisa ditandatangani tidak mematikan sesi): gate sebelum ready, coalescing, retry eksplisit, rotasi gagal tanpa
hapus kunci, server error, suspend/resume, clear saat enrollment aktif, late completion,
dan kegagalan penghapusan Keychain. Ini mock deterministic, bukan pengujian Secure Enclave fisik.
Build package iOS arm64 memeriksa integrasi APISZTA/platform. Sebelum rilis host CocoaPods,
jalankan pod install untuk memasukkan RILSession.swift baru. OneApp belum disinkronkan/diaktifkan;
verifikasi device, logout nyata, hard wipe, pinning dan production menunggu integrasi host.

AppBuilder di repository library telah diregenerasi Pods-nya. Lockfile lokal diselaraskan dari
NexilisZTA 1.3.0 ke podspec existing 1.3.1; versi dependency pihak ketiga tidak berubah.
Minimum deployment target project dan AppBuilderShare kini diselaraskan ke iOS 15.0 pada
Debug/Release, sama dengan target AppBuilder utama dan Pods. Override deployment target
pada perintah build tidak lagi diperlukan. Verifikasi Debug arm64 dilakukan tanpa signing;
instalasi perangkat tetap memerlukan signing/provisioning host yang valid.
