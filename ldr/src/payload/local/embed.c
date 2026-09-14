#include "../../../includes/core/core.h"
#include "../../../includes/payload/payload.h"





#if defined(PAYLOAD_SECTION_TEXT)
#pragma section(".text")
__attribute__((section(".text"))) CONST UCHAR Payload[] = {...};
#elif defined(PAYLOAD_SECTION_RDATA)
CONST UCHAR Payload[] = { ... };  
#elif defined(PAYLOAD_SECTION_DATA)
UCHAR Payload[] = { ... };        
#endif




LPVOID payload_get(PDWORD PayloadSize) {
    DWORD Size = sizeof(Payload);
    LPVOID addr = g_ldr->apis->LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, Size);
    if (!addr) return NULL;
    memcpy(addr, Payload, Size);
    *PayloadSize = Size;
    return addr;

}
