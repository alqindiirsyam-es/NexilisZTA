/*
 * rasp_native.c
 * Nexilis iOS ZTA Bundle V5 — RASP Native Implementation
 *
 */

#include "rasp_native.h"

#include <TargetConditionals.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#if defined(__APPLE__)
    #include <TargetConditionals.h>
    #if TARGET_OS_IPHONE
        // iOS: jangan include sys/ptrace.h
    #else
        #include <sys/ptrace.h>
    #endif
#else
    #include <sys/ptrace.h>
#endif
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/mach.h>
#include <pthread.h>
#include <time.h>
#include <fcntl.h>
#include "GlobalState.h"

void rasp_secure_zero(void *ptr, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) { *p++ = 0; }
}

#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif

#if TARGET_OS_IPHONE
extern int ptrace(int request, pid_t pid, caddr_t addr, int data);
#endif

/* -------------------------------------------------------------------------
 * Layer 1 — pure detectors (no state awareness). Logic unchanged from V4.
 * ---------------------------------------------------------------------- */

static bool check_suspicious_paths(void) {
    const char *paths[] = {
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/usr/lib/libjailbreak.dylib",
        "/var/lib/cydia",
        "/var/lib/apt",
        "/etc/apt",
        "/private/var/lib/apt",
        "/usr/sbin/sshd",
        "/usr/bin/ssh",
        "/bin/bash",
        "/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
        NULL
    };
    struct stat st;
    for (int i = 0; paths[i] != NULL; i++) {
        if (stat(paths[i], &st) == 0) {
            return true;
        }
    }
    return false;
}

static bool check_writable_system(void) {
    const char *test_path = "/private/nx_jb_probe";
    int fd = open(test_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        close(fd);
        unlink(test_path);
        return true;
    }
    return false;
}

static bool check_dyld_images_for(const char **needles) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name == NULL) continue;
        for (int j = 0; needles[j] != NULL; j++) {
            if (strstr(name, needles[j]) != NULL) {
                return true;
            }
        }
    }
    return false;
}

/* -------------------------------------------------------------------------
 * The one condition under which a probe that reports Xcode rather than the
 * device is left out of the build.
 *
 * Two things have to be true at once, and a shipping build can satisfy neither:
 * DEBUG is defined only by the Debug configuration, and __OPTIMIZE__ is defined
 * by the compiler itself whenever optimisation is on - which it is for Release,
 * for Archive, and therefore for anything that can reach TestFlight or the App
 * Store. Should DEBUG ever be set by hand in a release configuration, the
 * optimiser still gives it away and every probe below is compiled in full.
 * ---------------------------------------------------------------------- */
#if defined(DEBUG) && !defined(__OPTIMIZE__)
#define NX_XCODE_DEBUG_RUN 1
#endif

static bool check_env_injection(void) {
#if defined(NX_XCODE_DEBUG_RUN)
    /* Debug build only. Xcode sets DYLD_INSERT_LIBRARIES itself the moment any diagnostic is
     * switched on - the Main Thread Checker alone is enough - so under a Debug configuration
     * this reports an injected library that is Apple's own. Answered here rather than at the
     * places that ask, because two of them do: the jailbreak check and the injection check, and
     * gating only one leaves the other reporting the same thing.
     *
     * A Debug build never ships. Release compiles the real probe below. */
    return false;
#else
    const char *insert = getenv("DYLD_INSERT_LIBRARIES");
    return (insert != NULL && strlen(insert) > 0);
#endif
}

static bool check_symlinks(void) {
    struct stat st;
    if (lstat("/Applications", &st) == 0 && S_ISLNK(st.st_mode)) return true;
    if (lstat("/Library/Ringtones", &st) == 0 && S_ISLNK(st.st_mode)) return true;
    return false;
}

#if !defined(NEXILIS_APPSTORE_BUILD) && !defined(NX_XCODE_DEBUG_RUN)
static bool check_fork(void) {
    pid_t child = fork();
    if (child > 0) {
        int status = 0;
        waitpid(child, &status, 0);
        return true;
    } else if (child == 0) {
        _exit(0);
    }
    return false;
}
#endif

static bool nx_detect_jailbreak(void) {
    static const char *jb_libs[] = {
        "MobileSubstrate",
        "SubstrateLoader",
        "TweakInject",
        "libhooker",
        "substitute",
        NULL
    };

    if (check_suspicious_paths()) return true;
    if (check_writable_system())  return true;
    if (check_dyld_images_for(jb_libs)) return true;
    if (check_env_injection())    return true;
    if (check_symlinks())         return true;
#if !defined(NEXILIS_APPSTORE_BUILD) && !defined(NX_XCODE_DEBUG_RUN)
    /* Debug build only: fork() is a jailbreak tell because a shipped app is refused it. A
     * development-signed build carries get-task-allow and is allowed, so this reports a
     * jailbreak on every device the app is run from Xcode on - and forking a process that is
     * being debugged is its own trouble besides. Everything above still runs. */
    if (check_fork())             return true;
#endif
    return false;
}

static bool nx_detect_debugger(void) {
#if defined(NX_XCODE_DEBUG_RUN)
    /* Debug build only. Xcode attaches a debugger to every app it runs, so under a Debug
     * configuration this is not a finding - it is the build system doing its job, and
     * reporting it would leave the boot sequence stopping at status 4 with deviceClean = NO
     * for the whole session. A Debug build is never shipped; Release compiles the real check
     * below, untouched. */
    return false;
#else
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    struct kinfo_proc info;
    memset(&info, 0, sizeof(info));
    size_t size = sizeof(info);

    if (sysctl(mib, 4, &info, &size, NULL, 0) == 0) {
        return (info.kp_proc.p_flag & P_TRACED) != 0;
    }
    // sysctl itself failed — treat as inconclusive/hostile environment.
    return true;
#endif
}

static bool check_frida_port(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int result = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    close(sock);
    return (result == 0);
}

static bool check_frida_named_pipe(void) {
    struct stat st;
    return stat("/tmp/frida-server", &st) == 0 || stat("/tmp/re.frida.server", &st) == 0;
}

/*
 * F-5: Frida thread-name scan.
 *
 * An embedded, renamed FridaGadget presents no "frida" substring in its dylib
 * path and, in listen mode before a script attaches, hooks nothing — so the
 * image-name and port checks miss it. Its runtime threads, however, keep their
 * names. Enumerate the task's threads and match Frida's characteristic names.
 *
 * Note: "gmain"/"gdbus" are GLib thread names; iOS apps almost never link GLib,
 * so they are high-signal here. Remove them if a host app legitimately uses GLib.
 */
static bool check_frida_threads(void) {
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;
    if (task_threads(mach_task_self(), &threads, &count) != KERN_SUCCESS || threads == NULL) {
        return false;
    }

    static const char *needles[] = {
        "gum-js-loop", "gmain", "gdbus", "pool-frida", "pool-spawner", "frida", NULL
    };

    bool found = false;
    char name[64];
    for (mach_msg_type_number_t i = 0; i < count && !found; i++) {
        pthread_t pt = pthread_from_mach_thread_np(threads[i]);
        if (pt != NULL && pthread_getname_np(pt, name, sizeof(name)) == 0 && name[0] != '\0') {
            for (int j = 0; needles[j] != NULL; j++) {
                if (strstr(name, needles[j]) != NULL) { found = true; break; }
            }
        }
    }

    vm_deallocate(mach_task_self(), (vm_address_t)threads, count * sizeof(thread_act_t));
    return found;
}

static bool nx_detect_frida(void) {
    static const char *frida_names[] = {
        "FridaGadget",
        "frida-agent",
        "frida-gadget",
        "frida_agent",
        "libfrida",
        NULL
    };
    if (check_frida_port(27042)) return true;
    if (check_frida_port(27043)) return true;
    if (check_frida_port(27044)) return true;
    if (check_dyld_images_for(frida_names)) return true;
    if (check_frida_named_pipe()) return true;
    if (check_frida_threads()) return true;   // F-5
    return false;
}

static bool nx_detect_injection(void) {
    static const char *hook_libs[] = {
        "libcycript",
        "cynject",
        "libhooker",
        "SubstrateLoader",
        "fishhook",
        NULL
    };
    if (check_env_injection()) return true;
    if (check_dyld_images_for(hook_libs)) return true;
    return false;
}

static bool nx_detect_simulator(void) {
#if TARGET_OS_SIMULATOR
    return true;
#endif
    char machine[64] = {0};
    size_t len = sizeof(machine);
    int mib[2] = { CTL_HW, HW_MACHINE };
    if (sysctl(mib, 2, machine, &len, NULL, 0) == 0) {
        if (strstr(machine, "x86") != NULL || strstr(machine, "i386") != NULL) return true;
    }
    if (getenv("SIMULATOR_DEVICE_NAME") != NULL) return true;
    return false;
}

static bool nx_detect_reverse_tools(void) {
    static const char *tool_libs[] = {
        "libcycript",
        "RevealServer",
        "FLEXing",
        "FLEX",
        NULL
    };
    if (getenv("LLDB_DEBUGGER") != NULL) return true;
    if (getenv("_MSSafeMode") != NULL) return true;
    if (check_dyld_images_for(tool_libs)) return true;
    return false;
}

/* ---- B7: inline / prologue hook detection -------------------------------- */
/* A trampoline planted over a function prologue is, on ARM64, typically an
 * unconditional branch or an ADRP/BR pair as the FIRST instruction(s). We inspect
 * the prologues of the libc functions our own detection battery depends on
 * (stat, open, task_threads, sysctl) — the ones an attacker hooks to blind RASP. */
static bool prologue_is_branch(const void *fn) {
    if (fn == NULL) return false;
    const uint32_t *insn = (const uint32_t *)fn;
    uint32_t i0 = insn[0];
    /* ARM64 B (0x14000000 mask 0xFC000000) or BR Xn (0xD61F0000 mask 0xFFFFFC1F) */
    if ((i0 & 0xFC000000u) == 0x14000000u) return true;            /* B imm26 */
    if ((i0 & 0xFFFFFC1Fu) == 0xD61F0000u) return true;            /* BR Xn   */
    /* ADRP x16 + BR x16 trampoline */
    if ((i0 & 0x9F00001Fu) == 0x90000010u) {                        /* ADRP x16 */
        uint32_t i1 = insn[1];
        if ((i1 & 0xFFFFFC1Fu) == 0xD61F0000u) return true;         /* BR x16  */
    }
    return false;
}

static bool nx_detect_inline_hooks(void) {
    // Gunakan dlsym — hindari re-deklarasi extern yang konflik dengan sys/stat.h dan fcntl.h
    const void *targets[] = {
        dlsym(RTLD_DEFAULT, "stat"),
        dlsym(RTLD_DEFAULT, "open"),
        (const void *)&task_threads,
        NULL
    };
    for (int i = 0; targets[i] != NULL; i++) {
        if (prologue_is_branch(targets[i])) return true;
    }
    return false;
}

/* ---- B8: fishhook-style symbol rebinding --------------------------------- */
/* fishhook rewrites __la_symbol_ptr / __got slots. We resolve a handful of
 * imported symbols and confirm each target lies inside a legitimately mapped,
 * file-backed system image (dyld image range) rather than an app-writable or
 * anonymous region. Conservative: only flags clear out-of-image targets. */
static bool addr_in_any_dyld_image(uintptr_t addr) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header_64 *mh =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (mh == NULL) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const uint8_t *cmd = (const uint8_t *)(mh + 1);
        for (uint32_t c = 0; c < mh->ncmds; c++) {
            const struct load_command *lc = (const struct load_command *)cmd;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
                uintptr_t start = (uintptr_t)(seg->vmaddr + slide);
                uintptr_t end = start + (uintptr_t)seg->vmsize;
                if (addr >= start && addr < end) return true;
            }
            cmd += lc->cmdsize;
        }
    }
    return false;
}

static bool nx_detect_symbol_rebinding(void) {
    // Gunakan dlsym — hindari re-deklarasi extern yang konflik
    void *fns[] = {
        dlsym(RTLD_DEFAULT, "open"),
        (void *)&task_threads,
        NULL
    };
    for (int i = 0; fns[i] != NULL; i++) {
        if (!addr_in_any_dyld_image((uintptr_t)fns[i])) return true;
    }
    return false;
}

/* -------------------------------------------------------------------------
 * Layer 2 — GlobalState-gated boot sequence (Status FE 1-10).
 * Called once by rasp_run_boot_sequence() below, in exactly this order.
 * ---------------------------------------------------------------------- */

void rasp_deny_debugger_attach(void) {
    // Status FE 1 (RASP Pre-main Activation) must already be set by
    // RASPBridge +load before this runs.
    if (stateGet() != NX_STATE_RASP_PREMAIN) {
        return;
    }
#if TARGET_OS_IPHONE && !defined(NX_XCODE_DEBUG_RUN)
    /* Debug build only: this is what stops Xcode attaching at all, so a crash in a Debug run
     * cannot be looked at while it is armed. Not compiled into Release, where it is the whole
     * point of this function. The state still moves on either way, so the rest of the boot
     * sequence runs exactly as it does in a shipping build. */
    ptrace(PT_DENY_ATTACH, 0, 0, 0);
#endif
    stateSet(NX_STATE_ANTI_DEBUGGER_LOCK); // -> 2
}

bool rasp_check_jailbreak(void) {
    if (stateGet() != NX_STATE_ANTI_DEBUGGER_LOCK) {
        return true;
    }
    if (nx_detect_jailbreak()) {
        return true;
    }
    stateSet(NX_STATE_NATIVE_JAILBREAK_CHECK); // -> 3
    return false;
}

bool rasp_check_debugger(void) {
    if (stateGet() != NX_STATE_NATIVE_JAILBREAK_CHECK) {
        return true;
    }
    if (nx_detect_debugger()) {
        return true;
    }
    stateSet(NX_STATE_NATIVE_DEBUGGER_CHECK); // -> 4
    return false;
}

bool rasp_check_frida(void) {
    if (stateGet() != NX_STATE_NATIVE_DEBUGGER_CHECK) {
        return true;
    }
    if (nx_detect_frida()) {
        return true;
    }
    stateSet(NX_STATE_NATIVE_FRIDA_CHECK); // -> 5
    return false;
}

bool rasp_check_injection(void) {
    if (stateGet() != NX_STATE_NATIVE_FRIDA_CHECK) {
        return true;
    }
    if (nx_detect_injection()) {
        return true;
    }
    stateSet(NX_STATE_NATIVE_INJECTION_CHECK); // -> 6
    return false;
}

bool rasp_check_simulator(void) {
    if (stateGet() != NX_STATE_NATIVE_INJECTION_CHECK) {
        return true;
    }
    if (nx_detect_simulator()) {
        return true;
    }
    stateSet(NX_STATE_NATIVE_SIMULATOR_CHECK); // -> 7
    return false;
}

bool rasp_check_reverse_tools(void) {
    if (stateGet() != NX_STATE_NATIVE_SIMULATOR_CHECK) {
        return true;
    }
    if (nx_detect_reverse_tools()) {
        return true;
    }
    stateSet(NX_STATE_NATIVE_REVERSE_TOOL_CHECK); // -> 8
    return false;
}

bool rasp_check_inline_hooks(void) {
    if (stateGet() != NX_STATE_NATIVE_REVERSE_TOOL_CHECK) {
        return true;
    }
    if (nx_detect_inline_hooks()) {
        return true;
    }
    stateSet(NX_STATE_NATIVE_INLINE_HOOK_CHECK); // -> 9
    return false;
}

bool rasp_check_symbol_rebinding(void) {
    if (stateGet() != NX_STATE_NATIVE_INLINE_HOOK_CHECK) {
        return true;
    }
    if (nx_detect_symbol_rebinding()) {
        return true;
    }
    stateSet(NX_STATE_NATIVE_GOT_HOOK_CHECK); // -> 10
    return false;
}

uint32_t rasp_run_boot_sequence(void) {
    typedef bool (*check_fn)(void);
    struct { check_fn fn; uint32_t flag; } steps[] = {
        { rasp_check_jailbreak,        RASP_THREAT_JAILBREAK },
        { rasp_check_debugger,         RASP_THREAT_DEBUGGER },
        { rasp_check_frida,            RASP_THREAT_FRIDA },
        { rasp_check_injection,        RASP_THREAT_INJECTION },
        { rasp_check_simulator,        RASP_THREAT_SIMULATOR },
        { rasp_check_reverse_tools,    RASP_THREAT_REVERSE_TOOL },
        { rasp_check_inline_hooks,     RASP_THREAT_INLINE_HOOK },   /* B7 */
        { rasp_check_symbol_rebinding, RASP_THREAT_GOT_HOOK },      /* B8 */
    };
    int n = (int)(sizeof(steps) / sizeof(steps[0]));

    uint32_t threats = RASP_THREAT_NONE;
    for (int i = 0; i < n; i++) {
        // Fixed order — this chain IS the matrix order, not randomized.
        if (steps[i].fn()) {
            threats |= steps[i].flag;
            break;
        }
    }
    return threats;
}

/* -------------------------------------------------------------------------
 * Layer 1 entry point — periodic re-scan, unrelated to GlobalState.
 * ---------------------------------------------------------------------- */

typedef bool (*check_fn)(void);

uint32_t rasp_run_all_checks(void) {
    struct {
        check_fn fn;
        uint32_t flag;
    } checks[] = {
        { nx_detect_debugger,          RASP_THREAT_DEBUGGER },
        { nx_detect_jailbreak,         RASP_THREAT_JAILBREAK },
        { nx_detect_frida,             RASP_THREAT_FRIDA },
        { nx_detect_injection,         RASP_THREAT_INJECTION },
        { nx_detect_simulator,         RASP_THREAT_SIMULATOR },
        { nx_detect_reverse_tools,     RASP_THREAT_REVERSE_TOOL },
        { nx_detect_inline_hooks,      RASP_THREAT_INLINE_HOOK },   /* B7 */
        { nx_detect_symbol_rebinding,  RASP_THREAT_GOT_HOOK },      /* B8 */
    };
    int n = (int)(sizeof(checks) / sizeof(checks[0]));

    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)getpid();
    for (int i = n - 1; i > 0; i--) {
        seed = seed * 1103515245u + 12345u;
        int j = (int)((seed >> 16) % (unsigned int)(i + 1));
        check_fn tmpFn = checks[i].fn;
        uint32_t tmpFlag = checks[i].flag;
        checks[i].fn = checks[j].fn;
        checks[i].flag = checks[j].flag;
        checks[j].fn = tmpFn;
        checks[j].flag = tmpFlag;
    }

    uint32_t threats = RASP_THREAT_NONE;
    for (int i = 0; i < n; i++) {
        if (checks[i].fn()) {
            threats |= checks[i].flag;
        }
    }
    return threats;
}
