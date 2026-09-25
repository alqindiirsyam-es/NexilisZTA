# Client RIL — tahap 4–6 (library)

Lifecycle managed tahap 6 tersedia opt-in di repository library; lihat [RIL-LIFECYCLE.md](RIL-LIFECYCLE.md).
Contoh instalasi adapter manual di bawah adalah alternatif untuk host manual, bukan dipasang
bersamaan dengan konfigurasi managed. Integrasi repository OneApp tetap ditunda.

Status: core/library dan adapter networking endpoint pilot tersedia, dengan opt-in eksplisit.
Startup OneApp belum memasang adapter; perilaku default tetap existing. Tidak ada enrollment
otomatis dan policy backend tidak diaktifkan oleh perubahan ini.

## Komponen

| File | Fungsi |
| --- | --- |
| Source/RIL/RILCore.swift | Canonical URL, SHA-256 body, signature base, tiga header RIL-v2 |
| Source/RIL/RILKeyStore.swift | Kunci Secure Enclave P-256, wrapped representation dan state di Keychain |
| Source/RIL/RILClient.swift | Actor enrollment/rotasi, validasi challenge/respons, readiness dan signing |
| Source/RIL/RILPlatform.swift | Bridge sesi ZTA/App Attest dan transport HTTPS berpining tanpa redirect |
| Source/RIL/RILPilotTransport.swift | Allowlist method/path/origin dan signing byte final sebelum pengiriman |

Core menghasilkan `Content-Digest`, `Signature-Input`, dan `Signature` dengan covered components,
urutan parameter, nonce, query kosong `?`, public key SPKI DER, dan signature P1363 R||S yang
sesuai backend tahap 2–3. CryptoKit message-sign melakukan SHA-256 tepat sekali.
Core hanya menerima HTTPS, body materialized, tanpa Content-Encoding atau httpBodyStream.
Default ceiling 1 MiB dan lifetime 60 detik; policy boleh memperkecil batas. Backend pilot tetap
membatasi telemetry 256 KiB dan security-pack GET tanpa body/Content-Type.

## Aktivasi host lewat Info.plist (jalur yang disarankan)

Host tidak perlu menulis kode RIL. Seluruh alur — membaca identitas, memasang lifecycle, dan
tiga alert pemulihan (konfigurasi ditolak, enrollment gagal, telemetry ditahan) — ada di
`NexilisZTA/Source/RIL/RILHostIntegration.swift` dan dijalankan oleh `APISZTA.configure`.
Host hanya mendeklarasikan satu dictionary di `Info.plist`:

```xml
<key>NexilisRIL</key>
<dict>
    <key>Enabled</key>        <true/>
    <key>ApplicationID</key>  <string>TEAM123456.io.example.app</string>
    <key>BundleID</key>       <string>io.example.app</string>
    <key>Environment</key>    <string>production</string>
    <key>TenantID</key>       <string></string>
</dict>
```

- Tidak ada dictionary = host tidak opt-in, tidak ada yang berubah. `Enabled` `false` sama saja.
- Dictionary ada tapi salah (kunci kurang, `BundleID` tidak sama dengan bundle yang berjalan,
  `Environment` di luar `production`/`development`) → `APISZTA.configure` **berhenti** dengan
  `RILError.invalidConfiguration`, `onFailure` dipanggil, dan alert "Konfigurasi RIL tidak valid"
  tampil begitu ada layar. Build yang mendeklarasikan RIL tidak boleh diam-diam jalan tanpanya.
- `challengeURL` dan `enrollmentURL` diturunkan dari `challengeEndpoint` konfigurasi Sentinel
  (`…/zta/challenge` → `…/zta/ril/enroll`), policy `maxBodyBytes` 256 KiB.

Yang bisa diatur di `NexilisZTAConfiguration`:
- `rilInfoPlistKey` — nama kunci (bawaan `NexilisRIL`); `nil` mematikan pembacaan plist.
- `ril` — konfigurasi eksplisit; kalau diisi, plist diabaikan.
- `showsRILRecoveryUI` — `false` bila host menampilkan UI pemulihan sendiri lewat
  `APISZTA.rilSession`, `retryRILEnrollment()`, `isRILTelemetrySuspended`.

Host yang layar pertamanya mengganti root window beberapa saat setelah launch boleh mem-post
`Notification.Name.ztaHostInterfaceReady` setelah penggantian selesai; presenter juga mendeteksi
sendiri alert yang terbawa pergi oleh penggantian root dan menawarkannya lagi.

## Pemakaian API manual (host yang membangun konfigurasi sendiri)

Setelah konfigurasi pinning dan otorisasi ZTA/App Attest siap, host dapat membuat satu client
untuk konfigurasi berikut. Nilai contoh harus diganti konfigurasi deployment sebenarnya:

```swift
let rilConfiguration = try RILConfiguration(
    origin: "https://zta.example",
    appID: "TEAM123456.io.example.oneapp",
    bundleID: "io.example.oneapp",
    tenantID: "", // kosong hanya untuk aplikasi statis backend
    environment: "production", // environment App Attest aplikasi
    challengeURL: URL(string: "https://zta.example/zta/challenge")!,
    enrollmentURL: URL(string: "https://zta.example/zta/ril/enroll")!,
    policy: try RILPolicy(maxBodyBytes: 262144)
)
let ril = RILClient(configuration: rilConfiguration)
let keyID = try await ril.enroll()
let readiness = try await ril.readiness()

var request = URLRequest(url: URL(string: "https://zta.example/zta/security-pack")!)
request.httpMethod = "GET"
let signed = try await ril.sign(request)
// Kirim signed.request melalui transport berpining yang menangani expiry/retry/redirect.
// RILClient.sign sendiri tidak mengirim HTTP dan tidak memasang interceptor.
```

Endpoint dapat mencakup public prefix seperti `/zta-ios`, sesuai deployment. Origin tetap
scheme+host+port tanpa path. Tanda tangani URL publik final; jangan menghapus prefix setelah
signing. Daftar endpoint pilot diterapkan adapter di bawah. API bisnis NexilisLite/Alamofire,
upload, download, WebView, dan socket tetap di luar scope sampai verifier backend bisnis tersedia.

`RILCore.sign` adalah primitive yang menerima `RILSigningKey`, berguna untuk fixture/interoperabilitas.
Untuk production pakai `RILClient.sign`, yang memeriksa sesi ZTA, identitas App Attest, readiness,
origin, dan memasang token sesi saat ini. Return `RILSignedRequest.signatureBase` untuk diagnostik
test; jangan mencetaknya di production karena query dapat memuat data sensitif.

## Adapter networking pilot — tahap 5

`APISZTA.refreshSecurityIntelligence` dan `submitThreatTelemetry` sekarang melewati dispatch
adapter opsional. Host memasang satu kali, sebelum memulai polling/telemetry Sentinel:

```swift
let routes = try RILPilotRoutes(
    origin: rilConfiguration.origin,
    securityPackURL: URL(string: "https://zta.example/zta/security-pack")!,
    telemetryURL: URL(string: "https://zta.example/zta/telemetry/events")!
)
try APISZTA.installRILPilotTransport(RILPilotTransport(client: ril, routes: routes))
```

Gunakan URL publik yang sama dengan konfigurasi APISZTA, termasuk prefix deployment.
Instalasi tidak memerlukan enrollment selesai; sebelum ready, request pilot gagal lokal.
Bootstrap challenge/attest/assert/key/enroll tetap memakai jalurnya sendiri tanpa RIL.
Jangan menjalankan polling sebelum instalasi bila host hendak mengaktifkan RIL: request yang
sudah dikirim sebelum instalasi tidak dapat ditarik kembali. Pengurutan startup adalah tahap 6.

Setelah terpasang, tidak ada fallback unsigned atau API disable runtime. Allowlist memeriksa
origin, encoded path dan method persis, dengan query tetap tercakup signature. GET wajib kosong
tanpa Content-Type; POST maksimal 262144 byte dengan Content-Type JSON profil. Signing dilakukan
sesudah serialisasi terakhir, body tidak diubah. Setiap pemanggilan send membuat nonce baru.
Transport ephemeral berpining menolak redirect, cookies/cache dan response lebih dari 262144 byte.
Tidak ada retry otomatis atau penyesuaian jam otomatis, termasuk pada RIL_EXPIRED/CLOCK_SKEW.
Refresh GET berikutnya dapat membuat attempt baru. Status HTTP/body error server dikembalikan
oleh adapter tanpa reset kunci/sesi; APISZTA mempertahankan penanganan 401 existing saja.

Telemetry signed yang menerima non-2xx atau error sesudah transport mulai diperlakukan konservatif:
`APISZTA.isRILTelemetrySuspended` menjadi true dan timer tidak mengirim ulang batch. Buffer tidak
di-ack sebagai sukses. Ini juga berlaku untuk 403/409/503; belum ada retry terklasifikasi per kode.
Error sebelum pengiriman (misalnya belum enrolled/body terlalu besar) tetap mengikuti backoff
existing karena belum ada kemungkinan efek server. Host wajib menangani state suspended pada
tahap 6: rekonsiliasi pengiriman/deduplikasi, atau keputusan eksplisit membuang buffer, kemudian
`resumeRILTelemetryAfterReconciliation()`. Resume tidak boleh dipanggil otomatis oleh timer.
Latch dan buffer bersifat in-memory; tidak menambah antrean persisted/replay saat relaunch.
Mode legacy tanpa instalasi adapter mempertahankan perilaku retry existing.

## Penyimpanan dan keamanan kunci

Kunci RIL terpisah dari kunci App Attest/delivery/approval transaksi. Production hanya memakai
Secure Enclave; tidak ada fallback kunci software untuk simulator atau perangkat unsupported.
Signature rutin tidak meminta biometrik. Access control privateKeyUsage dan penyimpanan
AfterFirstUnlockThisDeviceOnly dimaksudkan agar background request bisa bekerja setelah unlock
pertama; perilakunya tetap perlu diuji pada iPhone terkunci/reboot sebelum rilis.

Satu Keychain generic-password item per scope origin/app/tenant/environment menyimpan wrapped
Secure Enclave representation, public key, active/candidate, dan status rotasi. Ini bukan raw
private scalar. Tidak disinkronkan iCloud dan tidak boleh dipindahkan ke perangkat lain.
Item rusak/gagal diakses tidak dianggap sebagai belum punya kunci dan tidak direset otomatis.
Identitas App Attest tersimpan harus cocok dengan identitas sesi saat operasi berjalan.

`clearLocalKeys()` hanya menghapus item kunci/state RIL lokal. Endpoint revocation server tetap
diperlukan untuk pencabutan server. Integrasi logout/hard wipe adalah pekerjaan tahap 6; API ini
belum dipanggil otomatis dari observer existing. Jangan memanggilnya untuk setiap timeout/403.

## Enrollment dan rotasi

- Candidate dibuat dan disimpan sebelum network request pertama. Timeout/restart memakai kembali
  candidate yang sama; tidak menghapus kunci lama atau menciptakan pasangan baru pada setiap retry.
- Challenge diverifikasi terhadap app/bundle/tenant/environment/origin, App Attest key ID,
  hash token sesi, purpose, profil, nonce, serta TTL. Jam perangkat boleh berbeda maksimal 60 detik
  saat enrollment; tidak ada perubahan jam sistem atau offset otomatis untuk request signing.
- Proof RIL menandatangani domain `NEXILIS-RIL-ENROLL-V1\n` + canonical JSON payload.
  App Attest kemudian melindungi payload beserta proof. Bridge menerima clientData mentah;
  AppAttestManager yang menghitung SHA-256 sekali sebelum API Apple.
- Token/key identity diperiksa sebelum dan sesudah pengiriman; perubahan sesi membuat operasi
  gagal tanpa menghapus candidate. Recovery berikutnya meminta challenge baru untuk sesi baru.
- Actor dan process-wide lease menolak operasi bersamaan pada scope sama dengan `RILError.busy`,
  termasuk bila host tidak sengaja membuat dua instance. Lease tidak mengoordinasikan extension
  proses lain; Keychain memakai app-default access group. Gunakan satu client per host/scope.
- Pemanggilan `rotate()` mendaftarkan candidate dengan replaces_key_id, menyimpan status menunggu
  konfirmasi, lalu meminta challenge baru dan mengirim confirm_rotation. Kunci lama hanya dibuang
  setelah konfirmasi backend dan commit lokal berhasil.
- Jika konfirmasi timeout, signing ditahan agar kunci lama yang mungkin sudah dicabut tidak
  digunakan. Panggil `enroll()` atau `rotate()` kembali untuk melanjutkan candidate/konfirmasi.
- `readiness()` dan fast path `enroll()` pada active key mencerminkan state lokal, bukan polling
  status registry backend. Error server key unavailable membutuhkan recovery terkontrol pada
  integrasi tahap 6; jangan menganggap readiness lokal sebagai otorisasi server.
- Assertion pada endpoint ZTA lain masih memakai alur existing. Counter App Attest global dapat
  memicu penolakan bila request tiba tidak berurutan; koordinasi/retry terbatas dengan challenge
  baru perlu diuji saat integrasi seluruh networking. Modul ini tidak mengganti alur assertion existing.

## Transport enrollment dan error

Transport default ephemeral URLSession, host wajib tercatat pada pinning RASPGuard; trust/pin
divalidasi melalui PinnedURLSessionDelegate existing. Tidak memakai cookie/cache/credential
storage. Redirect ditolak, URL response harus cocok, body respons dibatasi 262144 byte saat
dibaca secara streaming. Timeout request/resource 15/30 detik; tidak menunggu konektivitas tanpa batas.
Client tidak melakukan retry otomatis. HTTP non-200 menjadi `RILError.server(status:code:)`;
token/response body tidak dimasukkan ke error atau log. Error pinning/network diteruskan.

Signature pada security-pack/telemetry hanya aktif setelah host memasang adapter di atas.
Jangan aktifkan enforce sebelum tahap 6 memasang adapter, enrollment/lifecycle, dan recovery host.

## Pengujian yang disediakan

Di direktori NexilisZTA, contoh menjalankan test portable pada Mac (menggunakan temporary build directory):

```sh
ril_build_dir=$(mktemp -d /private/tmp/nexilis-ril-tests.XXXXXX)
xcrun swiftc -swift-version 5 -module-cache-path "$ril_build_dir/cache" \
  NexilisZTA/Source/NXLogger.swift NexilisZTA/Source/RIL/RILCore.swift \
  NexilisZTA/Source/RIL/RILKeyStore.swift \
  NexilisZTA/Source/RIL/RILClient.swift \
  NexilisZTA/Source/RIL/RILPilotTransport.swift \
  Tests/RIL/RILTests.swift -o "$ril_build_dir/ril-tests"
node Tests/RIL/verify-backend.js "$ril_build_dir/ril-tests" ../ServerZTAiOS
```

Untuk salinan OneApp, ganti argumen terakhir dengan path backend NexilisLibraryiOS/ServerZTAiOS.
Dependency Node memakai dependency backend existing; tidak ada tambahan dependency runtime iOS.

Test memakai kunci software hanya di file test dan storage memory; tidak menyentuh Keychain asli.
Menguji canonicalization/JSON, format signature/digest, batas request, penolakan sebelum enrollment,
storage failure, timeout/restart, rotasi, mismatch identitas/respons, dan serialisasi operasi.
Fixture signature dan CBOR sintetis dihasilkan Swift lalu diverifikasi modul enrollment/verifier
Node sebenarnya; request diterima, mutasi URL ditolak, dan replay ditolak. Tes tersebut tidak
menggantikan assertion Apple/Secure Enclave dari perangkat fisik.
Tahap 5 menambah pemeriksaan allowlist, byte final/batas body, nonce antar-attempt,
tanpa fallback/retry, status error dan penolakan redirect/response URL; total 56 pemeriksaan Swift.
Verifier backend juga menerima POST dari adapter, menolak body yang dimutasi serta replay GET/POST.

Build seluruh package NexilisZTA untuk arm64 iOS 15 juga diperiksa. Package.swift library utama
menyertakan direktori RIL; CocoaPods source glob existing mencakup file baru pada regenerasi pods.
Project pods OneApp yang sudah digenerate belum diperbarui; wiring OneApp tetap tahap 6.
Uji iPhone, Keychain setelah reboot, pinning koneksi nyata, dan backend production tetap dilakukan
bersama tahap integrasi sesuai rencana proyek.

Referensi platform: [Apple — Secure Enclave signing key](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey)
dan [Apple — P-256 signature raw representation](https://developer.apple.com/documentation/cryptokit/p256/signing/ecdsasignature/rawrepresentation).
