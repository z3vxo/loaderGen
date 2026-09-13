#include "includes/core/core.h"




#ifdef OUTPUT_DLL

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpvReserved) {
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
#ifndef OUTPUT_RUNDLL
        CreateThread(NULL, 0, LoadMain, hinstDLL, 0, NULL);
#endif
        break;
    }
    return TRUE;
}

#endif

#ifdef OUTPUT_RUNDLL
__declspec(dllexport) void CALLBACK rundll(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
    LoadMain((LPVOID)hinst);
}
#endif



#ifdef OUTPUT_EXE

int main() {

	if (!LoadMain(NULL)) return 1;

	return 0;
}

#endif

