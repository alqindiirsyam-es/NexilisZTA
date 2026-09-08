#ifndef GlobalState_h
#define GlobalState_h

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * NX flow states — this list mirrors the "Status FE" column of the
 * "Nexilis Mobile iOS Security Flow, Architecture & Capability Matrix"
 * (rows 1-15 / ZTA boot sequence). Every native/ObjC check that gates on
 * a previous step MUST use these constants instead of raw ints so the
 * code and the matrix never drift apart.
 *
 * The chain is STRICTLY SEQUENTIAL and is meant to run exactly once,
 * in this exact order, during app launch (RASPBridge +load -> RASPGuard
 * install). Periodic re-scans (RASPGuard startMonitoring timer) do NOT
 * use this chain — they call the underlying detectors directly — because
 * a monotonically increasing one-shot counter can never be satisfied twice.
 */
#define NX_STATE_IDLE                          0
#define NX_STATE_RASP_PREMAIN                  1  /* RASPBridge +load                         */
#define NX_STATE_ANTI_DEBUGGER_LOCK            2  /* rasp_deny_debugger_attach                */
#define NX_STATE_NATIVE_JAILBREAK_CHECK        3  /* rasp_check_jailbreak                     */
#define NX_STATE_NATIVE_DEBUGGER_CHECK         4  /* rasp_check_debugger                      */
#define NX_STATE_NATIVE_FRIDA_CHECK            5  /* rasp_check_frida                         */
#define NX_STATE_NATIVE_INJECTION_CHECK        6  /* rasp_check_injection                     */
#define NX_STATE_NATIVE_SIMULATOR_CHECK        7  /* rasp_check_simulator                     */
#define NX_STATE_NATIVE_REVERSE_TOOL_CHECK     8  /* rasp_check_reverse_tools                 */
#define NX_STATE_NATIVE_INLINE_HOOK_CHECK      9  /* rasp_check_inline_hooks         (B7)     */
#define NX_STATE_NATIVE_GOT_HOOK_CHECK         10 /* rasp_check_symbol_rebinding     (B8)     */
#define NX_STATE_CODE_SIGNATURE_VERIFY         11 /* verifyCodeSignatureIntegrity             */
#define NX_STATE_FAIL_CLOSED_READY             12 /* fail-closed path armed                   */
#define NX_STATE_STRING_OBFUSCATION_SELFTEST   13 /* StringEncryptor self-test                */
#define NX_STATE_CERT_PINNING_SETUP            14 /* setupCertificatePinning                  */
#define NX_STATE_PERIODIC_MONITORING           15 /* startMonitoring armed                    */
#define NX_STATE_APPATTEST_ENDPOINT_CONFIG     16 /* AppAttestService.configure               */
#define NX_STATE_APPATTEST_DEVICE_REGISTRATION 21 /* AppAttestManager registerDevice          */
#define NX_STATE_APPATTEST_ASSERTION           22 /* server-verified key-delivery assertion   */
#define NX_STATE_APPATTEST_KEY_DELIVERY        23 /* AppAttestManager requestKeyDelivery      */

int32_t stateGet(void);
void stateSet(int32_t state);

#ifdef __cplusplus
}
#endif

#endif /* GlobalState_h */
