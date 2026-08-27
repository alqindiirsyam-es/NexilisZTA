/*
 * rasp_native.h
 * Nexilis iOS ZTA Bundle V4 — Runtime Application Self-Protection (Native Layer)
 *
 * Defence-in-depth only. The hard trust gate is server-side App Attest validation.
 */

#ifndef NEXILIS_RASP_NATIVE_H
#define NEXILIS_RASP_NATIVE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RASP_THREAT_NONE            0x00000000
#define RASP_THREAT_JAILBREAK       0x00000001
#define RASP_THREAT_DEBUGGER        0x00000002
#define RASP_THREAT_FRIDA           0x00000004
#define RASP_THREAT_INJECTION       0x00000008
#define RASP_THREAT_SIMULATOR       0x00000010
#define RASP_THREAT_REVERSE_TOOL    0x00000020
#define RASP_THREAT_TAMPERED        0x00000040
#define RASP_THREAT_HOOK_DETECTED   0x00000080
/* B7 — inline/prologue hook on critical libc functions */
#define RASP_THREAT_INLINE_HOOK     0x00000100
/* B8 — fishhook-style GOT/PLT symbol rebinding */
#define RASP_THREAT_GOT_HOOK        0x00000200

void rasp_deny_debugger_attach(void);

bool rasp_check_debugger(void);
bool rasp_check_jailbreak(void);
bool rasp_check_frida(void);
bool rasp_check_injection(void);
bool rasp_check_simulator(void);
bool rasp_check_reverse_tools(void);
/* B7 */ bool rasp_check_inline_hooks(void);
/* B8 */ bool rasp_check_symbol_rebinding(void);

/* Periodic re-scan (used by RASPGuard's monitoring timer). Order is randomized
 * each call and is INDEPENDENT of the GlobalState boot-sequence counter. */
uint32_t rasp_run_all_checks(void);

uint32_t rasp_run_boot_sequence(void);

void rasp_secure_zero(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* NEXILIS_RASP_NATIVE_H */
