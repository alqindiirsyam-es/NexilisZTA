# Panduan Embed NexilisLite + NexilisZTA

Untuk host app apa pun — UIKit, SwiftUI, Flutter, React Native. Contoh di sini memakai Flutter
karena itu kasus yang paling sering ditanyakan, tapi tidak ada yang khusus Flutter di dalamnya:
yang berlaku adalah `AppDelegate` Swift-nya.

Dokumen ini menggantikan potongan-potongan lama yang beredar. Sejak rilis terakhir ada tiga
perubahan yang mengubah cara memasang, dan ketiganya ada di sini:

1. Kontrol keamanan Sentinel tidak lagi bergantung pada **mode aplikasi**, melainkan pada
   **ada-tidaknya token terbitan server**. Mode 3 yang daring dan terattestasi kini mendapat
   kontrol yang sama dengan mode 1 dan 2.
2. Build **Release** yang diperkeras wajib membawa kunci obfuscation sendiri, dan **gagal
   kompilasi** kalau kuncinya tidak ada.
3. `NexilisZTAConfiguration` punya beberapa properti baru — endpoint status, penanda tangan paket
   kebijakan, pin multi-host, dan mode aplikasi.

Rujukan yang lebih dalam untuk lapisan ZTA saja: `NexilisZTA/PANDUAN-INTEGRASI.md`
(entitlement, privacy shield, secure input, RASP). Untuk perbedaan mode 1/2/3 baris demi baris:
`REMEDIATION_DOCS/SECURITY-LEVELS.md`.

---

## 1. Dua pustaka, satu rantai

| | Isi | Wajib? |
|---|---|---|
| **NexilisZTA** | RASP, App Attest, certificate pinning, Sentinel (paket kebijakan, telemetri, kill switch), secure input | Ya — NexilisLite bergantung padanya |
| **NexilisLite** | CPaaS: chat, panggilan, konferensi, berkas | Ya, kalau Anda memakai fitur CPaaS |

Urutannya selalu sama dan tidak boleh dibalik: **ZTA memverifikasi dulu, CPaaS menyambung
kemudian.** `APIS.connect` dipanggil di dalam closure keberhasilan `APISZTA.configure`, bukan
sejajar dengannya. Sesi CPaaS tidak boleh berjalan di belakang pemeriksaan yang gagal.

---

## 2. Prasyarat

- **iOS 15.0** ke atas.
- **Perangkat fisik.** Simulator tidak didukung — `nuSDKService` hanya mengirim slice `ios-arm64`
  untuk perangkat. Ini bukan pilihan gaya; podspec-nya menyatakan hal yang sama lewat
  `EXCLUDED_ARCHS[sdk=iphonesimulator*]`. Build simulator akan gagal dengan
  `unsupported Swift architecture`.
- **Entitlement App Attest** (lihat bagian 4). Tanpa ini attestation tidak pernah lulus.
- Xcode dengan Swift 5.5+.

---

## 3. Pemasangan

### 3a. CocoaPods (disarankan)

```ruby
platform :ios, '15.0'

target 'Runner' do          # Flutter memakai nama target 'Runner'
  use_frameworks!

  pod 'NexilisLite', '~> 6.0'
  pod 'NexilisZTA',  '~> 1.3'
end
```

Untuk Flutter, blok di atas masuk ke `ios/Podfile` **di dalam** `target 'Runner' do` yang sudah
ada — jangan membuat target baru. Lalu:

```sh
cd ios && pod install
```

Selalu buka `.xcworkspace`, bukan `.xcodeproj`.

### 3b. Swift Package Manager

Keduanya punya `Package.swift`. Tambahkan lewat **File → Add Package Dependencies**:

```
https://github.com/alqindiirsyam-es/NexilisZTA.git   → 1.3.0 ke atas
https://github.com/alqindiirsyam-es/NexilisLite.git  → 6.0.0 ke atas
```

Cukup tambahkan **NexilisLite** saja kalau Anda memakai CPaaS — ia sudah menarik NexilisZTA
sebagai dependensi yang dideklarasikan, karena API publiknya menyebut tipe milik ZTA
(`APIS.configureSentinel` menerima `NexilisZTAConfiguration`).

Batasan simulator yang sama berlaku di SPM.

---

## 4. Entitlement dan capability

Di target app → **Signing & Capabilities** → tambah **App Attest**:

```xml
<key>com.apple.developer.devicecheck.appattest-environment</key>
<string>development</string>   <!-- production untuk TestFlight & App Store -->
```

Ini yang paling sering terlewat. **Tanpa entitlement ini, App Attest tidak jalan sama sekali** —
registrasi selalu gagal, closure `onReady` tidak pernah dipanggil, dan aplikasi tampak menggantung
di layar verifikasi. Untuk Flutter, berkas yang perlu disunting adalah
`ios/Runner/Runner.entitlements` — dan periksa juga varian lain kalau proyek Anda punya
(`RunnerDebug.entitlements`, `RunnerProfile.entitlements`, dan sejenisnya). Melewatkan satu varian
berarti konfigurasi build itu yang gagal.

---

## 5. Kode minimum — mode 3 (Regular)

Ini bentuk paling ringkas dan sudah benar untuk sebagian besar host:

```swift
import UIKit
import Flutter
import NexilisLite
import NexilisZTA

@main
@objc class AppDelegate: FlutterAppDelegate {

  private let appName = "NamaAplikasiAnda"
  private let apiKey  = "<API KEY DARI TIM NEXILIS>"

  private let ztaBaseURL    = "https://nexilis.io/zta-ios"
  private let ztaPrimaryPin = "sha256/tIAA8SPvbLBRxOAeQYkymqN3MhVpPuJFAbfLxihiMAU="
  private let ztaBackupPin  = "sha256/<PIN CADANGAN>"

  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    startNexilis()
    observeLifecycle()

    GeneratedPluginRegistrant.register(with: self)
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  private func startNexilis() {
    // Satu konfigurasi, dipakai dua kali: sekali untuk menjalankan rantai verifikasi,
    // sekali supaya lapisan CPaaS tahu mode dan kebijakan yang sama.
    var sentinel = NexilisZTAConfiguration(
      baseURL:    ztaBaseURL,
      appName:    appName,
      apiKey:     apiKey,
      primaryPin: ztaPrimaryPin,
      backupPin:  ztaBackupPin
    )
    sentinel.appMode = .regular          // 3 — bawaan; lihat bagian 6

    APIS.configureSentinel(sentinel)

    APISZTA.configure(sentinel, onFailure: { error in
      print("[Nexilis] verifikasi ZTA gagal: \(error.localizedDescription)")
    }) { [weak self] in
      guard let self else { return }
      // Hanya sampai di sini kalau verifikasi lulus.
      APIS.connect(appName: self.appName, apiKey: self.apiKey, delegate: self)
    }
  }

  private func observeLifecycle() {
    let center = NotificationCenter.default
    center.addObserver(forName: UIApplication.didEnterBackgroundNotification,
                       object: nil, queue: .main) { _ in APIS.enterBackground() }
    center.addObserver(forName: UIApplication.willEnterForegroundNotification,
                       object: nil, queue: .main) { _ in APIS.enterForeground() }
    center.addObserver(forName: UIApplication.willTerminateNotification,
                       object: nil, queue: .main) { _ in APIS.willTerminate() }
  }
}

extension AppDelegate: ConnectDelegate {
  func onSuccess(userId: String) { print("[Nexilis] connect berhasil, userId=\(userId)") }
  func onFailed(error: String)   { print("[Nexilis] connect gagal: \(error)") }
}
```

### Kenapa lifecycle lewat notifikasi

`FlutterAppDelegate` tidak mendeklarasikan `applicationDidEnterBackground` dan kerabatnya, jadi
meng-`override` metode itu tidak sah. Memakai `NotificationCenter` juga membuat kode Anda tidak
bergantung pada detail internal Flutter yang bisa berubah antar versi.

### Bentuk ringkas tanpa `NexilisZTAConfiguration`

Masih didukung dan cocok untuk uji coba cepat:

```swift
APISZTA.configure(
  baseURL: ztaBaseURL, appName: appName, apiKey: apiKey,
  primaryPin: ztaPrimaryPin, appAttest: true,
  onFailure: { error in print(error) }
) { APIS.connect(appName: appName, apiKey: apiKey, delegate: self) }
```

Kekurangannya: mode aplikasi tidak pernah sampai ke lapisan CPaaS karena
`APIS.configureSentinel` tidak dipanggil. Ini kebetulan bekerja — `APIS.connect` yang dipanggil
dari dalam `onReady` menemukan otorisasi sudah hidup lalu meneruskan begitu saja — tapi ia
bergantung pada urutan itu. Untuk produksi, pakai bentuk lengkap di atas.

### Format pin

`NexilisZTA` menuntut bentuk **`sha256/<base64>`**. Kalau nilai Anda disalin dari konfigurasi
Android (`ztaProtector` di `build.gradle`), di sana pin disimpan sebagai base64 polos tanpa
awalan — tambahkan `sha256/` di depannya.

---

## 6. Mode aplikasi: yang berubah

`appMode` ada tiga, sama dengan `APIS.setAppMode(mode:)` dan sama dengan SDK Android.

| | 1 HSA | 2 Middle | 3 Regular (bawaan) |
|---|---|---|---|
| Masuk aplikasi tanpa jaringan | tidak bisa | tidak bisa | **bisa** |
| App Attest | wajib | wajib | layanan yang menentukan |
| Traffic ditahan di belakang token | ya | ya | tidak |
| Kunci master di balik biometrik | ya | ditawarkan | sesuai kebijakan layanan |
| Ancaman runtime mencabut sesi | ya, proses dihentikan | ya | dilaporkan saja |

**Yang berubah:** dulu kontrol Sentinel — paket kebijakan bertanda tangan, telemetri ancaman,
kill switch, jangkar audit, transaksi sensitif — hanya berjalan di mode 1 dan 2. Sekarang
gerbangnya adalah **token terbitan server**, bukan mode. Artinya:

- Mode 3 **daring dan terattestasi** → punya token → mendapat semua kontrol itu.
- Mode 3 **luring** → tidak ada token → semuanya dilewati, aplikasi tetap terbuka.

Jadi yang membedakan mode sekarang adalah **toleransi terhadap keadaan luring**, bukan
kelengkapan kontrol keamanannya.

> **Konsekuensi praktis:** kalau Anda menyetel `appAttest: false`, tidak ada attestation, tidak ada
> token, dan **tidak ada satu pun kontrol Sentinel yang berjalan** — meskipun perangkat daring.
> Setelan itu hanya untuk integrasi awal, sebelum Team ID dan bundle identifier Anda terdaftar di
> layanan ZTA. Jangan dibawa ke produksi.

### Menyalakan paket kebijakan bertanda tangan

Paket kebijakan hanya diterima kalau host memberi kunci publik penanda tangannya:

```swift
sentinel.securityPackSignerSPKIBase64 = "<SPKI DER base64 dari tim Nexilis>"
```

Tanpa nilai ini setiap paket ditolak dan klien memakai kebijakan yang dikompilasi di dalamnya —
aman, hanya tidak bisa diperbarui dari jarak jauh.

---

## 7. Build Release: kunci obfuscation per-build

**Ini yang paling mungkin menghentikan build Anda setelah upgrade.**

String sensitif di NexilisZTA dienkripsi saat kompilasi. Dua kunci cadangan tersimpan di dalam
source, yang berarti bukan rahasia dari siapa pun yang bisa membaca repositori. Build Release yang
menyatakan dirinya diperkeras karena itu **wajib membawa kunci sendiri**, dan kunci yang hilang
atau bernilai nol menghentikan kompilasi:

```
StringEncryptor.h:40: error: "Release hardening requires per-build
NEXILIS_XOR_KEY and NEXILIS_XOR_KEY2 injected by CI"
```

Ini disengaja. Diam-diam jatuh ke kunci cadangan berarti IPA yang terkirim mengenkripsi string
dengan kunci yang sudah dipegang penyerang — dan tidak ada yang terlihat salah sampai seseorang
menjalankan `strings` pada IPA itu.

**Kalau Anda tidak memakai pengerasan** (tidak mendefinisikan `NEXILIS_RELEASE_HARDENING`), tidak
ada yang perlu dilakukan — build berjalan seperti biasa dengan kunci cadangan.

**Kalau Anda memakainya**, jalankan sebelum tiap build Release:

```sh
python3 tools/generate_release_secrets.py \
        <lokasi>/SentinelPerBuildSecrets.xcconfig
```

Lalu lampirkan `SentinelReleaseHardening.xcconfig` ke target pustaka **dan** aplikasi, dan
`SentinelReleaseHardening-App.xcconfig` ke target aplikasi saja. Berkas kuncinya masuk
`.gitignore`, tidak pernah di-commit, dan sebaiknya dibangkitkan ulang tiap rilis — dua rilis yang
berbagi kunci berbagi pula usaha untuk membobolnya.

Detail lengkap ada di dalam komentar kedua berkas `xcconfig` tersebut, termasuk dua jebakan yang
sudah terbukti memakan waktu: `STRIP_STYLE` menggagalkan target pustaka, dan
`GCC_SYMBOLS_PRIVATE_EXTERN` menyembunyikan simbol yang justru merupakan antarmuka sebuah
framework.

### Paruh kedua: identitas rilis

Pengerasan punya dua paruh, dan yang di atas baru paruh **biner** — enkripsi string, strip simbol,
kunci per-build. Paruh **identitas** memberi tahu gerbang integritas RASP siapa yang seharusnya
menjalankan kode ini: bundle id, application id, team id, dan environment App Attest.

Keduanya berkas terpisah karena isinya berbeda sifat. Yang biner sama untuk semua host. Yang
identitas berisi bundle dan team id sungguhan milik Anda, jadi ia per-host dan tidak masuk source
control — polanya sama persis dengan `SentinelPerBuildSecrets.xcconfig`.

Salin templatnya, isi keempat nilainya, dan letakkan di sebelah berkas hardening:

```sh
cp Hardening/HardenedRelease.xcconfig.example Hardening/HardenedRelease.xcconfig
```

```
GCC_PREPROCESSOR_DEFINITIONS = $(inherited) \
  NEXILIS_EXPECTED_BUNDLE_ID=\"com.perusahaan.app\" \
  NEXILIS_EXPECTED_APP_ID=\"TEAMID.com.perusahaan.app\" \
  NEXILIS_EXPECTED_TEAM_ID=\"TEAMID\" \
  NEXILIS_EXPECTED_APPATTEST_ENV=\"production\"
```

`post_install` di `Podfile` sudah menyisipkan kedua berkas ke konfigurasi Release target pustaka.
`#include?` memakai tanda tanya, jadi selama berkas identitas belum ada, tidak ada yang berubah:
gerbang di `RASPGuard.m` menuntut **keempat** makro sebelum ikut terkompilasi, jadi tiga yang hilang
membuatnya tetap di luar binary — sama seperti sebelum Anda membaca bagian ini.

**Keempat-empatnya, atau tidak sama sekali.** Mengisi sebagian tidak mengaktifkan apa pun, dan itu
justru pernah menjadi jebakan di repositori ini: satu makro terdefinisi sendirian selama beberapa
rilis, terlihat seperti pemeriksaan yang menyala padahal tidak pernah terkompilasi.

**Jangan pernah memakai `$(PRODUCT_BUNDLE_IDENTIFIER)` untuk nilai-nilai ini.** Berkas identitas
dilampirkan ke target **pod**, dan di sana variabel itu meresolusi ke bundle id pod
(`org.cocoapods.NexilisZTA`), bukan milik aplikasi Anda. Hasilnya perbandingan yang selalu gagal
dan `RASP_THREAT_TAMPERED` di setiap peluncuran build rilis. Nilainya harus literal.

Alasan yang sama berlaku untuk jalur runtime: `NexilisZTAConfiguration.expectedBundleID` dan
kembarannya juga harus nilai yang Anda tulis sendiri, bukan yang dibaca dari `Bundle.main`.
Membaca identitas dari bundle yang sedang diperiksa berarti membandingkan sesuatu dengan dirinya
sendiri — aplikasi yang dibungkus ulang membawa `Info.plist`-nya sendiri, dan perbandingan itu akan
lolos.

Verifikasi setelah mengisinya:

```sh
xcodebuild -showBuildSettings -project Pods/Pods.xcodeproj \
           -target NexilisZTA -configuration Release \
  | grep GCC_PREPROCESSOR_DEFINITIONS
```

Keempat `NEXILIS_EXPECTED_*` harus muncul berdampingan dengan `NEXILIS_RELEASE_HARDENING=1` dan
kedua kunci XOR.

### Jangan matikan simbol debug

Kalau target aplikasi Anda menyetel `GCC_GENERATE_DEBUGGING_SYMBOLS = NO`, **nyalakan kembali**.
Setelan itu terdengar mengeraskan, padahal tidak: dSYM tidak pernah ikut ke perangkat pengguna,
jadi menahannya tidak menyembunyikan apa pun dari penyerang. Yang membersihkan binary terkirim
adalah tahap *strip*, dan itu tetap berjalan. Yang hilang justru kemampuan Anda membaca laporan
crash dari kode aplikasi sendiri — termasuk penghentian oleh RASP, kegagalan attestation, dan bug
memori, yang semuanya muncul sebagai crash.

Terukur pada satu aplikasi nyata: menyalakannya membuat binary terkirim **1.137.744 → 1.121.248
byte**, dengan nol simbol lokal di kedua keadaan.

Yang perlu dijaga adalah dSYM-nya sendiri: ia memetakan alamat ke nama fungsi dan menyimpan jalur
sumber lengkap, jadi jangan pernah di-commit dan jangan disebar di luar tim.

---

## 8. Verifikasi pemasangan

Urutan yang benar saat aplikasi dijalankan di perangkat:

1. Log RASP muncul sebelum apa pun (dipasang dari `+load`).
2. `APISZTA.configure` berjalan: pin dipasang → feature access → App Attest (registrasi,
   assertion, key delivery).
3. Closure `onReady` dipanggil **satu kali**.
4. `APIS.connect` menyambung, lalu `onSuccess(userId:)` dipanggil.

Kalau berhenti sebelum langkah 3, periksa berurutan:

| Gejala | Penyebab paling sering |
|---|---|
| Attestation selalu gagal | Entitlement App Attest belum ada, atau ada di satu varian `.entitlements` saja |
| `unsupported Swift architecture` | Membangun untuk Simulator — tidak didukung |
| Verifikasi menggantung, tidak ada log | `onFailure` tidak dipasang, jadi errornya tidak terlihat |
| Pin ditolak | Pin tanpa awalan `sha256/`, atau pin milik host lain |
| Tidak ada telemetri / paket kebijakan | `appAttest: false`, atau perangkat luring — tidak ada token, semua kontrol dilewati |
| Build Release berhenti di `StringEncryptor.h` | Kunci per-build belum dibangkitkan (bagian 7) |

---

## 9. Fitur opsional

Privacy shield (menutup layar saat screenshot atau perekaman), penolakan keyboard pihak ketiga,
input sensitif, WebView aman, notifikasi ancaman RASP, dan penghapusan jejak sesi — semuanya
dijelaskan di `NexilisZTA/PANDUAN-INTEGRASI.md` bagian 8. Tidak diulang di sini karena tidak ada
yang berubah pada bagian itu.
