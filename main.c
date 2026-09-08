#include "includes/main/core.h"



#ifdef OUTPUT_DLL

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fwReason, LPVOID lpvReserved) {
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH: 
		CreateThread(NULL, 0, LoadMain, NULL, 0, NULL);
	case DLL_PROCESS_DETACH:
		break;
						   

	}
	
}

#endif


#ifdef OUTPUT_EXE
int main() {

	if (!LoadMain()) return 1;


	return 0;
}

#endif // DEBUG

