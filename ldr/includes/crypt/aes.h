#ifndef _AES_H_
#define _AES_H_

#include <windows.h>

#define AES_BLOCKLEN 16
#define AES_KEYLEN 32
#define AES_keyExpSize 240

struct AES_ctx
{
    BYTE RoundKey[AES_keyExpSize];
    BYTE Iv[AES_BLOCKLEN];
};

void AES_init_ctx(struct AES_ctx* ctx, const BYTE* key);
void AES_init_ctx_iv(struct AES_ctx* ctx, const BYTE* key, const BYTE* iv);
void AES_ctx_set_iv(struct AES_ctx* ctx, const BYTE* iv);
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, BYTE* buf, SIZE_T length);

#endif // _AES_H_
