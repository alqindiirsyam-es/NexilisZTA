# RIL untuk semua HTTPS — `RILProtection`

Kode: `NexilisZTA/Source/RIL/RILProtection.swift`, `RILClient.signForRelyingParty`,
`RILSession.signForRelyingParty`. Sisi server: `ServerZTAiOS/RIL-RELYING-PARTY.md`.

Dengan RIL aktif dan protection dikonfigurasi, setiap request HTTPS aplikasi ke URL yang
dilindungi keluar dalam keadaan ditandatangani oleh kunci RIL instalasi (Secure Enclave, profil
`nexilis-ril-v2`). Ini berlaku untuk backend NexilisLite dan API host sendiri. Backend
memverifikasinya lewat server ZTA (`POST /zta/ril/verify`). Berjalan sama di metode
**Embedded** (CocoaPods/SPM) dan **Shielding** (tanpa kode).

## Cara kerja

- `RILSigningURLProtocol` dipasang di depan setiap `URLSession` yang dibuat dari
  `URLSessionConfiguration.default`/`.ephemeral` (sesi Lite, Alamofire, sesi host) dan di
  `URLSession.shared`. Host maupun Lite tidak perlu mengubah kode. Protokol hanya mengambil
  request yang URL-nya diawali prefix yang dilindungi; request lain tidak disentuh.
- Untuk request yang diambil: body dibaca (maks 1 MiB), byte finalnya ditandatangani, lalu
  dikirim dari sesi protokol sendiri dan responsnya diteruskan apa adanya.
  - Header yang ditambahkan: `Signature`, `Signature-Input`, `Content-Digest`,
    `X-Nexilis-ZTA-Binding`.
  - `X-Nexilis-ZTA-Session` dihapus. Token sesi ZTA tidak pernah dikirim ke backend lain.
- Challenge TLS tetap diteruskan ke delegate sesi host, jadi pinning host tetap bekerja. Untuk
  host yang di-pin di RASPGuard (`PinnedHostPins`), pin SDK diperiksa lebih dulu.
- Tidak pernah diambil:
  - URL layanan ZTA sendiri (`baseURL`; rute pilot punya jalur RIL sendiri, dan chain ZTA tidak
    boleh menunggu RIL).
  - Request yang sudah membawa `Signature-Input`.
  - Non-HTTPS.
- Redirect: request baru ditandatangani ulang jika ikut dilindungi.

## Mode

| Mode | Perilaku |
| --- | --- |
| `enforce` (default) | Tidak ada tanda tangan berarti request gagal. Kasusnya: kunci RIL belum siap dalam `ReadinessTimeout` (default 15 s), body lebih dari 1 MiB, atau upload task yang body-nya tidak bisa dibaca protokol. Error domain `io.nexilis.ril.protection`: `-7510` belum siap, `-7511` body tidak bisa ditandatangani, `-7512` upload, `-7513` RIL tidak dikonfigurasi. |
| `observe` | Ditandatangani jika bisa, dikirim tanpa tanda tangan jika tidak (dicatat di log). Untuk rollout sebelum backend menegakkan. |

Kegagalan satu request (body terlalu besar, rotasi kunci sedang berjalan, sesi ZTA sedang
diperbarui) tidak mematikan sesi RIL. Hanya kegagalan kunci itu sendiri yang membuat sesi
`failed`.

## Konfigurasi

Kuncinya sama di Info.plist `NexilisRIL` (Embedded) dan di `NexilisShield.plist` `RIL`
(Shielding):

```xml
<key>NexilisRIL</key>                 <!-- di NexilisShield.plist: <key>RIL</key> -->
<dict>
  <key>Enabled</key>            <true/>
  <key>ApplicationID</key>      <string>TEAMID.com.example.app</string>
  <key>BundleID</key>           <string>com.example.app</string>
  <key>Environment</key>        <string>production</string>
  <key>TenantID</key>           <string>tenant id app di console ZTA</string>
  <key>ProtectedURLs</key>      <array><string>https://api.example.com/v1/</string></array>
  <key>ExcludedURLs</key>       <array><string>https://api.example.com/v1/upload</string></array>
  <key>ProtectionMode</key>     <string>enforce</string>
  <key>ProtectNexilisLite</key> <true/>
  <key>ReadinessTimeout</key>   <integer>15</integer>
</dict>
```

- `TenantID` harus sama dengan tenant app di server. Jika salah, log akan menampilkan
  `challenge identity mismatch: tenant_id`.
- `ProtectNexilisLite` melindungi base URL backend NexilisLite (dibaca per request karena bisa
  berubah setelah connect), kecuali endpoint `uploader*`. Di Shielding, butuh stage NexilisLite.
- Tanpa `ProtectedURLs`/`ProtectNexilisLite`: hanya rute pilot ZTA yang ditandatangani, seperti
  sebelumnya. Protection tanpa RIL `Enabled`, atau kunci yang salah bentuk, membuat
  `APISZTA.configure` gagal (tidak diam-diam berjalan tanpa RIL).
- Butuh chain ZTA karena kunci di-enroll dengan sesi ZTA. Kombinasi tanpa ZTA (SS saja, Lite
  saja, SS+Lite dengan `zta: false`) tidak bisa memakai RIL; CLI shield menolaknya.

Alternatif lewat kode (Embedded):

```swift
var config = NexilisZTAConfiguration(...)
config.ril = try RILConfiguration(...)                       // atau Info.plist NexilisRIL
config.rilProtection = try RILProtection(urlPrefixes: ["https://api.example.com/v1/"],
                                         excludedURLPrefixes: ["https://api.example.com/v1/upload"],
                                         mode: .enforce, protectsNexilisLite: true)
APISZTA.configure(config) { ... }   // atau APIS.configureSentinel(config) + APIS.connect
```

## API untuk yang tidak lewat URLSession

- `APISZTA.rilSign(_ request:) async throws -> URLRequest` dan versi `completion`. Untuk
  WKWebView, HTTP dari Dart (Flutter `HttpClient` tidak memakai URLSession; teruskan lewat
  method channel), upload di background session, atau host yang ingin menandatangani secara
  eksplisit. Body harus di `httpBody`, maks 1 MiB.
- `APISZTA.addRILProtectedURLs(_:excluding:)`: menambah prefix saat runtime.
- `APISZTA.isRILProtectionActive`.
- `RILSigningURLProtocol`: untuk sesi yang dibuat dari konfigurasi sendiri sebelum
  `APISZTA.configure` berjalan, tambahkan manual:
  `configuration.protocolClasses = [RILSigningURLProtocol.self] + (configuration.protocolClasses ?? [])`.

## Urutan dan batasan

- Protokol dipasang saat `APISZTA.configure` (Embedded) atau saat shield start (Shielding),
  sebelum chain berjalan. Sesi yang sudah dibuat sebelum itu tidak ikut, kecuali
  `URLSession.shared`.
- Tidak terjangkau: WKWebView, Dart `HttpClient`, `URLSessionConfiguration.background`. Untuk
  ketiganya gunakan `rilSign`.
- Progres upload (`didSendBodyData`) tidak dilaporkan untuk request yang ditandatangani. Body
  dibaca utuh lebih dulu, jadi kecualikan endpoint upload besar.
- Koneksi TLS protokol dipakai bersama antar-sesi host. Delegate host menerima challenge saat
  koneksi baru dibuka, bukan pada setiap request. Pin yang wajib berlaku di setiap koneksi
  sebaiknya dimasukkan ke `PinnedHostPins` ZTA, yang diperiksa SDK di setiap koneksi.
- Tanda tangan hanya berguna jika backend memverifikasinya. Lihat
  `ServerZTAiOS/RIL-RELYING-PARTY.md`: backend Lite/CPaaS dan API host perlu memasang guard atau
  memanggil `/zta/ril/verify`.

## Uji

- `node --test ril-enrollment.test.js ril-verifier.test.js ril-relying-party.test.js` di
  `ServerZTAiOS`.
- Interop Swift → Node dan lifecycle: perintah di `RIL-CLIENT.md` dan `RIL-LIFECYCLE.md`.
  Interop sekarang mencakup tanda tangan relying party yang diverifikasi `/zta/ril/verify`.
- Device iPhone 7 (iOS 15.8, Flutter Embedded, enforce): enrollment berhasil, dan semua request
  ditandatangani dengan nonce berbeda. Yang diuji: GET `URLSession.shared`, POST JSON dan form
  (sesi default/ephemeral), redirect, upload task yang body-nya terbaca, dan `rilSign` manual.
  `X-Nexilis-ZTA-Session` tidak pernah ikut terkirim, dan URL yang dikecualikan tidak
  ditandatangani. Catatan iOS 15: membaca `URLProtocol.task` di dalam `startLoading` membuat app
  abort, sehingga protokol mencatat jenis task dari initializer.
- Device iPhone 17 Pro (iOS 26, Flutter Embedded dan Shielding + NexilisLite). Enrollment di iOS 26
  menunggu deploy perbaikan server `authenticatorData` 99 byte; sampai itu, hasil yang teruji:
  - enforce menolak saat kunci belum siap (`-7510`);
  - URL yang dikecualikan lewat tanpa tanda tangan;
  - di observe, body JSON/form, redirect, dan upload lewat utuh;
  - challenge TLS koneksi pertama sampai ke delegate host.
