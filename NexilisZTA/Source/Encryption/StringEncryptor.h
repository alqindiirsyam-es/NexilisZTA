/*
 * StringEncryptor.h
 * Nexilis iOS ZTA — Multi-step compile-time string encryption
 *
 * Upgrade dari single-XOR ke double-XOR + byte-shuffle.
 * Masih compile-time (constexpr), tidak ada overhead runtime yang berarti.
 * ENCRYPTED_NSSTRING() tersedia di .mm (Obj-C++) dan .m (Obj-C fallback).
 */

#ifndef NEXILIS_STRING_ENCRYPTOR_H
#define NEXILIS_STRING_ENCRYPTOR_H

#import <Foundation/Foundation.h>

#ifdef __cplusplus
#include <array>
#include <cstddef>
#include <cstdint>

// Dua layer kunci: XOR pertama + XOR kedua setelah shuffle
// Produksi: inject NEXILIS_XOR_KEY dan NEXILIS_XOR_KEY2 via CI, jangan hardcode di repo
#ifndef NEXILIS_XOR_KEY
#define NEXILIS_XOR_KEY  0x5AU
#endif

#ifndef NEXILIS_XOR_KEY2
#define NEXILIS_XOR_KEY2 0xA3U
#endif

namespace nexilis {

constexpr size_t _gcd(size_t a, size_t b) {
    return b == 0 ? a : _gcd(b, a % b);
}

// Fix: the stride was a flat 7, and `i * 7 + 11 (mod N)` only visits every slot when 7 and N are
// coprime. Whenever the length is a multiple of 7 - "OneApp" is one, N being 7 - several source
// indices shuffle onto the same slot, the rest are never written, and what comes back out is not
// what went in. The largest stride that is coprime with this particular N, so the map is always a
// permutation and always reversible.
constexpr size_t _stride(size_t N) {
    size_t s = 7;
    while (s > 1 && _gcd(s, N) != 1) {
        --s;
    }
    return s;
}

// Shuffle deterministik berbasis indeks — tidak pakai random agar constexpr
// Fix: returned uint8_t, which silently truncated every index past 255 on a string longer than
// that and mapped it onto the wrong slot.
constexpr size_t _shuffle_idx(size_t i, size_t N) {
    return (i * _stride(N) + 11u) % N;
}

// Decrypt index: cari posisi asli dari index terenkripsi
constexpr size_t _unshuffle_idx(size_t enc_i, size_t N) {
    for (size_t orig = 0; orig < N; ++orig) {
        if (_shuffle_idx(orig, N) == (enc_i % N)) return orig;
    }
    return enc_i; // fallback (tidak seharusnya terjadi)
}

template <std::size_t N, uint8_t Key1, uint8_t Key2>
struct EncString final {
    std::array<uint8_t, N> data{};

    constexpr explicit EncString(const char (&literal)[N]) : data{} {
        // Step 1: XOR pertama
        std::array<uint8_t, N> tmp{};
        for (std::size_t i = 0; i < N; ++i) {
            tmp[i] = static_cast<uint8_t>(literal[i]) ^ Key1;
        }
        // Step 2: shuffle deterministik
        for (std::size_t i = 0; i < N; ++i) {
            data[_shuffle_idx(i, N)] = tmp[i];
        }
        // Step 3: XOR kedua pada posisi sudah di-shuffle
        for (std::size_t i = 0; i < N; ++i) {
            data[i] ^= Key2;
        }
    }
};

} // namespace nexilis

static inline NSString *nx_decrypt_multistep(const uint8_t *enc, size_t len,
                                              uint8_t key1, uint8_t key2) {
    if (len == 0) return @"";
    char *buf = (char *)alloca(len);

    // Undo step 3: XOR kedua
    uint8_t *tmp = (uint8_t *)alloca(len);
    for (size_t i = 0; i < len; i++) {
        tmp[i] = enc[i] ^ key2;
    }
    // Undo step 2: unshuffle
    for (size_t enc_i = 0; enc_i < len; enc_i++) {
        size_t orig = nexilis::_unshuffle_idx(enc_i, len);
        buf[orig] = (char)tmp[enc_i];
    }
    // Undo step 1: XOR pertama (sudah di buf)
    for (size_t i = 0; i < len; i++) {
        buf[i] = (char)((uint8_t)buf[i] ^ key1);
    }

    if (len > 0 && buf[len - 1] == '\0') {
        return [NSString stringWithUTF8String:buf];
    }
    return [[NSString alloc] initWithBytes:buf length:len encoding:NSUTF8StringEncoding];
}

#define ENCRYPTED_NSSTRING(literal)                                                 \
    ({                                                                               \
        constexpr auto _nxEnc = nexilis::EncString<sizeof(literal),                 \
                                    (uint8_t)NEXILIS_XOR_KEY,                       \
                                    (uint8_t)NEXILIS_XOR_KEY2>(literal);            \
        nx_decrypt_multistep(_nxEnc.data.data(), _nxEnc.data.size(),               \
                             (uint8_t)NEXILIS_XOR_KEY, (uint8_t)NEXILIS_XOR_KEY2); \
    })

#else
// Fallback untuk pure .m files — plaintext tapi konsisten di Debug build
static inline NSString *ENCRYPTED_NSSTRING_RUNTIME(const char *plaintext) {
    return [NSString stringWithUTF8String:plaintext];
}
#define ENCRYPTED_NSSTRING(literal) ENCRYPTED_NSSTRING_RUNTIME(literal)
#endif

#endif /* NEXILIS_STRING_ENCRYPTOR_H */
