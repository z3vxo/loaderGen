#include "../../includes/core/core.h"
#include "../../includes/crypt/crypt.h"



void rc4_init(unsigned char* key, unsigned char* s, int keyLenght) {
	int i, j = 0;
	unsigned char temp;

	for (i = 0; i < 256; i++) {
		s[i] = (unsigned char)i;
	}

	for (i = 0; i < 256; i++) {
		j = (j + s[i] + key[i % keyLenght]) % 256;
		temp = s[i];
		s[i] = s[j];
		s[j] = temp;
	}
}

void rc4_crypt(unsigned char* data, int DataLength, unsigned char* s) {
	int i = 0, j = 0, k;
	unsigned char temp;


	for (k = 0; k < DataLength; k++) {
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;
		temp = s[i];
		s[i] = s[j];
		s[j] = temp;

		data[k] ^= s[(s[i] + s[j]) % 256];
	}
}

void crypt_decrypt(unsigned char* buf, int bufLen, unsigned char* key, int keyLen, unsigned char* nonce, int nonceLen) {
	unsigned char s[256];
	rc4_init(key, s, keyLen);
	rc4_crypt(buf, bufLen, s);
}

