/*
 * StringEncryptor.mm
 * Nexilis iOS ZTA — Runtime selftest untuk multi-step encryption
 */

#import "StringEncryptor.h"

__attribute__((constructor))
static void _nx_string_encryptor_selftest(void) {
#ifdef __cplusplus
    // Verifikasi bahwa encrypt-decrypt round-trip bekerja benar
    NSString *value = ENCRYPTED_NSSTRING("NEXILIS_ZTA_CHECK");
    if (![value isEqualToString:@"NEXILIS_ZTA_CHECK"]) {
        // Enkripsi/dekripsi rusak — trap sebelum app berjalan
        __builtin_trap();
    }
    // Test string pendek (1 char) untuk edge case shuffle
    NSString *single = ENCRYPTED_NSSTRING("X");
    if (![single isEqualToString:@"X"]) {
        __builtin_trap();
    }
#endif
}
