#include "../../../includes/core/core.h"
#include "../../../includes/payload/payload.h"



// local payload file for basic embed, .text, .rdata/data

#if defined(PAYLOAD_SECTION_TEXT)
#pragma section(".text")
__declspec(allocate(".text")) CONST UCHAR Payload[] = { ... };
#elif defined(PAYLOAD_SECTION_RDATA)
CONST UCHAR Payload[] = { ... };  // CONST already puts it in .rdata
#elif defined(PAYLOAD_SECTION_DATA)
UCHAR Payload[] = { ... };        // mutable -> .data
#endif



#ifdef PAYLOAD_LOCAL_EMBED
LPVOID payload_get(PDWORD PayloadSize) {
	DWORD Size = sizeof(Payload);
    *PayloadSize = Size;
    return Payload;

}
#endif