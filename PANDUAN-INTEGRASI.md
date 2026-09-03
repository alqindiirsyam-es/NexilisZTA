# Panduan Integrasi NexilisZTA

Panduan langkah demi langkah memasang **NexilisZTA** ke project iOS milik host.

NexilisZTA adalah lapisan pengamanan Zero Trust: RASP (deteksi jailbreak, debugger, Frida, injeksi, inline/GOT hook, verifikasi code signature), App Attest beserta key delivery, certificate pinning dengan rotasi, secure input, privacy shield, dan session teardown.

---

## Prasyarat

| Butuh | Keterangan |
| --- | --- |
| iOS 15.0 | Deployment target minimum pod |
| CocoaPods | Dipasang lewat pod, sama seperti NexilisLite |
| `use_frameworks!` | Pod ini dynamic framework |
| Xcode dengan `gnu++20` | Sudah diatur pod, host tidak perlu apa-apa |
| Akun Apple Developer | App Attest butuh entitlement yang harus di-enable di provisioning profile |
| Endpoint ZTA | Server harus menyediakan tujuh endpoint (lihat Langkah 7) |

NexilisZTA **tidak punya dependency apa pun**, termasuk ke NexilisLite. Jadi bisa dipasang di project yang tidak memakai produk Nexilis lainnya.

---

## Langkah 1 — Tambahkan pod

Salin folder `NexilisZTA/` ke samping project host, lalu di `Podfile`:

```ruby
platform :ios, '15.0'

target 'NamaAppAnda' do
  use_frameworks!
  pod 'NexilisZTA', :path => '../NexilisZTA'
end
```

```bash
pod install
```

Setelah ini buka `.xcworkspace`, bukan `.xcodeproj` lagi.

> **Catatan:** kalau deployment target app lebih tinggi dari pod, tambahkan `post_install` seperti pada project OneApp agar semua pod ikut naik.

---

## Langkah 2 — Entitlements

Tiga hal berikut **tidak bisa dibawa oleh library** karena melekat pada app yang ditandatangani. Host wajib menambahkannya sendiri.

### 2a. App Attest (wajib)

Di target app → **Signing & Capabilities** → tambah **App Attest**. Hasilnya di file `.entitlements`:

```xml
<key>com.apple.developer.devicecheck.appattest-environment</key>
<string>production</string>
```

Pakai `development` selama pengujian dengan build debug, `production` untuk TestFlight dan App Store.

Tanpa entitlement ini App Attest **tidak jalan sama sekali** — registrasi akan selalu gagal.

### 2b. WiFi info (opsional)

Hanya kalau memakai `NetworkPosture` untuk membaca SSID:

```xml
<key>com.apple.developer.networking.wifi-info</key>
<true/>
```

### 2c. Info.plist (opsional)

Hanya kalau memakai `GeofencePolicy`:

```xml
<key>NSLocationWhenInUseUsageDescription</key>
<string>Digunakan untuk memverifikasi lokasi perangkat.</string>
```

---

## Langkah 3 — Import

Tidak perlu bridging header. Seluruh header Objective-C dan C sudah menjadi public header pod, jadi cukup:

```swift
import NexilisZTA
```

Dari situ Swift bisa mengakses `RASPGuard`, `AppAttestManager`, `AppAttestService`, `stateGet()`/`stateSet()`, konstanta `NX_STATE_*`, dan fungsi `NXEncrypted*`.

---

## Langkah 4 — Satu panggilan

Panggil sekali di `application(_:didFinishLaunchingWithOptions:)`, sebelum ada request apa pun ke jaringan. Closure terakhirnya dipanggil **hanya kalau seluruh pemeriksaan lulus**, dan di situlah host memulai sesinya sendiri.

```swift
func application(_ application: UIApplication,
                 didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {

    APISZTA.configure(
        baseURL:    "https://server-anda.com/zta-ios",
        appName:    "NamaAppAnda",
        apiKey:     "…",
        primaryPin: "sha256/…"
    ) {
        // Baru di sini sesi host dimulai. Kalau verifikasi gagal, blok ini tidak pernah jalan.
        APIS.connect(appName: "NamaAppAnda", apiKey: "…", delegate: self)
    }

    return true
}
```

Di balik satu panggilan itu berjalan:

| Tahap | Isi |
| --- | --- |
| Pin | `RASPGuard` dipasangi primary dan backup pin |
| Feature access | tanya server apakah app ini memang wajib attestation |
| App Attest | registrasi kalau belum terdaftar, lalu assertion, lalu key delivery |
| Percobaan ulang | enam kali diam-diam dengan jeda membesar sampai 16 detik |
| Jaringan mati | rantai diparkir, bukan dihitung gagal, dan lanjut sendiri saat jaringan kembali |
| Layar gagal | `ZTAErrorViewController` muncul setelah percobaan otomatis habis |

Rantai RASP — jailbreak, debugger, Frida, injection, hook, state 1 sampai 15 — sudah jalan sebelum semua ini: `RASPBridge` memasangnya dari `+load`, sebelum `main`.

### Parameter

| Parameter | Arti |
| --- | --- |
| `baseURL` | akar layanan ZTA, dengan atau tanpa garis miring di ujung |
| `appName`, `apiKey` | identitas host di sisi Nexilis |
| `primaryPin` | SPKI pin host ZTA, bentuk `sha256/<base64>`. Nil memakai pin bawaan |
| `backupPin` | pin tujuan rotasi. Nil memakai bawaan |
| `featureAccessURL` | sumber policy feature access. Nil memakai URL bawaan, yang **tidak** diturunkan dari `baseURL` |
| `showsErrorScreen` | `false` kalau host mau menampilkan layar gagalnya sendiri |
| `onFailure` | dipanggil setelah percobaan otomatis habis, membawa error yang menghentikan rantai |

Tujuh endpoint diturunkan otomatis dari `baseURL` dengan path baku: `/zta/challenge`, `/zta/attest`, `/zta/assert`, `/zta/status/verify`, `/zta/register`, `/zta/key`, `/zta/revoke`. Kalau ada yang berbeda, susun `NexilisZTAConfiguration` sendiri lalu oper ke `APISZTA.configure(_:showsErrorScreen:onFailure:onReady:)`.

### Kalau host mau layar gagalnya sendiri

```swift
APISZTA.configure(
    baseURL: "…", appName: "…", apiKey: "…", primaryPin: "sha256/…",
    showsErrorScreen: false,
    onFailure: { error in
        // tampilkan layar sendiri; panggil APISZTA.retry() dari tombol coba lagi
    }
) {
    APIS.connect(appName: "…", apiKey: "…", delegate: self)
}
```

### Kalau host mau menjalankan rantainya sendiri

`APISZTA.applyConfiguration(_:)` menyimpan konfigurasi, memasang pin dan mengisi endpoint App Attest, lalu berhenti di situ. Sesudahnya host memanggil `AppAttestService` tahap demi tahap seperti pada Langkah 5. Ini jalur yang dipakai OneApp sebelum semua ini ada.

### Mendapatkan nilai pin

```bash
openssl s_client -connect server-anda.com:443 </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl base64
```

Hasilnya diberi awalan `sha256/`. Isi `backupPin` dengan hash sertifikat pengganti supaya rotasi tidak mengunci pengguna.

---

## Langkah 5 — Alur verifikasi

Rantainya berurutan ketat dan hanya boleh jalan sekali per launch. Setiap tahap menolak berjalan kalau tahap sebelumnya belum tercapai — ini disengaja, agar tidak bisa dilompati.

```
RASPBridge +load  →  RASPGuard install  →  state 1-15
configure         →  state 16
registerDevice    →  state 21
performAssertion  →  state 22
requestKeyDelivery→  state 23   ← baru di sini app boleh jalan
```

`APISZTA.configure` menjalankan seluruh urutan itu dan memeriksa sendiri bahwa state berakhir di 23 sebelum memanggil closure sukses. Bagian di bawah ini hanya diperlukan host yang memilih jalur manual lewat `applyConfiguration`.

```swift
private func mulaiVerifikasi() {
    let service = AppAttestService.shared

    guard service.isSupported else {
        // Perangkat di bawah A12 atau iOS 15 — App Attest tidak tersedia.
        // Putuskan sendiri: lanjut tanpa attestation, atau tolak.
        lanjutKeAplikasi()
        return
    }

    if service.isRegistered {
        assertionLaluKeyDelivery()
    } else {
        service.registerDevice { [weak self] berhasil, error in
            guard berhasil else {
                self?.tampilkanGagal(error)
                return
            }
            self?.assertionLaluKeyDelivery()
        }
    }
}

private func assertionLaluKeyDelivery() {
    AppAttestService.shared.performAssertion { [weak self] berhasil, error in
        guard berhasil else {
            self?.tampilkanGagal(error)
            return
        }
        AppAttestService.shared.requestKeyDelivery { key, error in
            guard let key else {
                self?.tampilkanGagal(error)
                return
            }
            // key siap dipakai
            self?.lanjutKeAplikasi()
        }
    }
}
```

### Pastikan tahapnya benar sebelum melanjutkan

```swift
private func lanjutKeAplikasi() {
    guard stateGet() == NX_STATE_APPATTEST_KEY_DELIVERY else {
        let error = NSError(
            domain: NXAppAttestErrorDomain,
            code: Int(stateGet()),
            userInfo: [
                NSLocalizedDescriptionKey: "Perangkat, jaringan, sistem atau aplikasi tidak memenuhi syarat keamanan.",
                NSLocalizedFailureReasonErrorKey: "Berhenti pada tahap \(stateGet())."
            ]
        )
        tampilkanGagal(error)
        return
    }
    // … lanjutkan startup app di sini
}
```

Pengecekan ini penting: tanpa itu, app yang gagal di tengah rantai tetap jalan seolah verifikasinya lulus. Lewat `APISZTA.configure` pemeriksaan ini sudah dilakukan library.

---

## Langkah 6 — Layar gagal dan percobaan ulang

Kegagalan datang sebagai `NSError` berdomain `NXAppAttestErrorDomain`, dengan `code` berisi nomor tahap terakhir yang tercapai — ini yang dipakai support untuk melacak macetnya di mana.

Sebagian besar kegagalan sifatnya sesaat: jaringan belum siap sedetik setelah app di-resume, atau layanan attestation Apple sedang sibuk. `APISZTA` sudah menangani itu sendiri:

- enam percobaan diam-diam, jeda 2, 4, 8, 16, 16 detik, sebelum pengguna melihat apa pun
- kegagalan tanpa jaringan tidak menghabiskan jatah percobaan, rantai diparkir sampai jaringan kembali
- app yang kembali ke depan setelah gagal mencoba lagi dengan sendirinya
- `ZTAErrorViewController` muncul setelah jatah habis, lengkap dengan tombol **Coba Lagi**, satu percobaan otomatis lagi setelah 15 detik, dan tautan **Hubungi Support**

Tombol Coba Lagi memanggil `APISZTA.retry()`, yang membuang dulu registrasi lama sebelum mengulang — registrasi yang sudah rusak akan gagal dengan cara yang sama persis kalau dipakai ulang. Host bisa memanggil `APISZTA.retry()` sendiri dari mana saja.

Kalau host mau mengamati tanpa closure, tersedia tiga notifikasi dengan nama yang sama seperti sebelumnya: `.ztaSessionReady`, `.ztaSessionError` yang membawa `userInfo["error"]`, dan `.ztaSessionRetry` yang meminta rantai diulang.

Alamat pada tautan Hubungi Support diambil dari `supportEmail` di `NexilisZTAConfiguration`, bawaannya `support@nexilis.io`.

---

## Langkah 7 — Sisi server

Server host harus menyediakan tujuh endpoint di bawah `baseURL`:

| Endpoint | Fungsi |
| --- | --- |
| `POST /zta/challenge` | Memberi nonce untuk attestation |
| `POST /zta/attest` | Memvalidasi attestation object dari Apple |
| `POST /zta/register` | Menyimpan keyId perangkat |
| `POST /zta/assert` | Memvalidasi assertion tiap launch |
| `POST /zta/status/verify` | Mengecek status perangkat |
| `POST /zta/key` | Mengirim decryption key setelah perangkat lolos |
| `POST /zta/revoke` | Mencabut registrasi perangkat |

Body `register` dan `key` menyertakan `bundle_id` serta device posture dari RASP (`threat_mask`, `rasp_clean`, `os_version`, `device_model`). Server yang memutuskan apakah posture itu layak diberi key — inilah gerbang kepercayaan sebenarnya; RASP di sisi perangkat hanya lapisan tambahan.

---

## Langkah 8 — Fitur opsional

Semua di bawah ini berdiri sendiri, pakai seperlunya.

### Privacy shield — menutup layar saat screenshot / perekaman

```swift
PrivacyShield.shared().install(with: window)
```

> Di Objective-C namanya `+sharedShield`; Swift mengimpornya sebagai `shared()`.

### Menolak keyboard pihak ketiga

```swift
func application(_ application: UIApplication,
                 shouldAllowExtensionPointIdentifier id: UIApplication.ExtensionPointIdentifier) -> Bool {
    return SecureInput.rejectCustomKeyboards(id)
}
```

### Input sensitif

Ganti `UITextField` untuk PIN/password dengan `SensitiveTextField`, atau pakai `SecureNumericKeypad` untuk papan angka dengan tata letak acak:

```swift
let field = SensitiveTextField()
let keypad = SecureNumericKeypad(maxLength: 6)
```

### WebView aman

```swift
let webView = WKWebView(frame: .zero,
                        configuration: SecureWebViewFactory.hardenedConfig())

// Kalau perlu membatasi navigasi ke host tertentu saja:
let guardDelegate = SecureWebViewFactory.makeNavigationGuard(
    allowedHosts: ["server-anda.com"]
)
webView.navigationDelegate = guardDelegate   // simpan referensinya, jangan sampai dilepas ARC
```

Tersedia juga `firstPartyConfig(messageHandler:…)` untuk webview yang perlu bertukar pesan dengan native.

### Notifikasi ancaman RASP

```swift
RASPGuard.shared().delegate = self

func raspGuard(_ guard: RASPGuard, didDetectThreats threats: UInt32) {
    // Konstanta RASP_THREAT_* datang dari makro C, terbaca sebagai Int32 di Swift.
    if threats & UInt32(RASP_THREAT_JAILBREAK) != 0 { /* … */ }
}

func raspGuard(_ guard: RASPGuard, didDetectPinningFailureForHost host: String) {
    // pinning gagal — pertimbangkan menghentikan sesi
}
```

### Menghapus jejak sesi

```swift
SecureWipe.secureWipe(hard: true)   // hard = kondisi tamper/duress
```

---

## Langkah 9 — Verifikasi pemasangan

**1. Build bersih di Debug dan Release**

```bash
xcodebuild -workspace NamaApp.xcworkspace -scheme NamaApp \
  -configuration Release -sdk iphoneos -destination 'generic/platform=iOS' build
```

**2. Pastikan konstanta tidak terbaca polos di binary**

```bash
strings NexilisZTA.framework/NexilisZTA | grep -c "server-anda.com"
# harus 0
```

**3. Pastikan rantai state sampai ujung**

Tambahkan sementara `print(stateGet())` sebelum melanjutkan startup. Nilai akhir harus **23** (`NX_STATE_APPATTEST_KEY_DELIVERY`). Kalau berhenti di angka lain, itu nomor tahap yang macet — cocokkan dengan daftar `NX_STATE_*` di `GlobalState.h`.

**4. Uji di perangkat asli**

App Attest tidak jalan di simulator. Perangkat butuh chip A12 ke atas dan iOS 16 ke atas; di bawah itu `isSupported` mengembalikan `false` dan host yang menentukan mau lanjut atau tidak.

---

## Masalah yang mungkin muncul

| Gejala | Penyebab | Solusi |
| --- | --- | --- |
| `error: constexpr variable '_nxEnc' must be initialized by a constant expression` | Standar C++ di bawah `gnu++20` | Sudah diatur pod; muncul kalau `CLANG_CXX_LANGUAGE_STANDARD` di-override host |
| `Undefined symbols: _NXEncryptedAPIBaseURL` | Deklarasi keluar dari blok `extern "C"` di `EncryptedStrings.h` | Kembalikan ke dalam blok |
| Registrasi App Attest selalu gagal | Entitlement App Attest belum ada, atau environment salah | Cek Langkah 2a; `development` untuk debug, `production` untuk rilis |
| String konfigurasi terbaca di binary | `EncryptedStrings` berekstensi `.m`, bukan `.mm` | `ENCRYPTED_NSSTRING` hanya mengenkripsi di bawah `__cplusplus` |
| Assertion gagal terus padahal registrasi berhasil | Registrasi basi setelah reinstall atau ganti environment | `AppAttestManager.shared().clearRegistration()` lalu daftar ulang |
| App jalan padahal verifikasi gagal | Tidak ada pengecekan `stateGet()` sebelum lanjut | Lihat Langkah 5 |

---

## Catatan keamanan

- **Nilai yang dioper lewat `configure` adalah literal milik host**, dan hanya sekuat cara host menyamarkannya. Kalau ingin perlakuan yang sama seperti konstanta bawaan, pakai `ENCRYPTED_NSSTRING` di sisi host dengan call site dikompilasi sebagai Objective-C++.
- **Gerbang kepercayaan ada di server.** RASP dan pengecekan di perangkat bisa dilewati oleh penyerang yang menguasai perangkat itu; yang tidak bisa dipalsukan adalah validasi attestation di sisi server. Jangan jadikan hasil `deviceClean` sebagai satu-satunya penentu.
- **Rantai state hanya sekali per launch.** Pemindaian berkala (`startMonitoring`) memanggil detektor secara langsung dan tidak memakai rantai ini, karena penghitung satu arah tidak mungkin dipenuhi dua kali.
