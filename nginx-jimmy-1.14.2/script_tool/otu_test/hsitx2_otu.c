#include "hsitx2_otu.h"

#include <stdio.h>
#include <openssl/aes.h>
#include <time.h>

#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#ifdef b64_USE_CUSTOM_MALLOC
extern void* b64_malloc(size_t);
#endif

#ifdef b64_USE_CUSTOM_REALLOC
extern void* b64_realloc(void*, size_t);
#endif


unsigned char *
b64_decode_ex (const char *src, size_t len, size_t *decsize) {
  int i = 0;
  int j = 0;
  int l = 0;
  size_t size = 0;
  unsigned char *dec = NULL;
  unsigned char buf[3];
  unsigned char tmp[4];

  // alloc
  dec = (unsigned char *) b64_malloc(1);
  if (NULL == dec) { return NULL; }

  // parse until end of source
  while (len--) {
    // break if char is `=' or not base64 char
    if ('=' == src[j]) { break; }
    if (!(isalnum(src[j]) || '+' == src[j] || '/' == src[j])) { break; }

    // read up to 4 bytes at a time into `tmp'
    tmp[i++] = src[j++];

    // if 4 bytes read then decode into `buf'
    if (4 == i) {
      // translate values in `tmp' from table
      for (i = 0; i < 4; ++i) {
        // find translation char in `b64_table'
        for (l = 0; l < 64; ++l) {
          if (tmp[i] == b64_table[l]) {
            tmp[i] = l;
            break;
          }
        }
      }

      // decode
      buf[0] = (tmp[0] << 2) + ((tmp[1] & 0x30) >> 4);
      buf[1] = ((tmp[1] & 0xf) << 4) + ((tmp[2] & 0x3c) >> 2);
      buf[2] = ((tmp[2] & 0x3) << 6) + tmp[3];

      // write decoded buffer to `dec'
      dec = (unsigned char *) b64_realloc(dec, size + 3);
      if (dec != NULL){
        for (i = 0; i < 3; ++i) {
          dec[size++] = buf[i];
        }
      } else {
        return NULL;
      }

      // reset
      i = 0;
    }
  }

  // remainder
  if (i > 0) {
    // fill `tmp' with `\0' at most 4 times
    for (j = i; j < 4; ++j) {
      tmp[j] = '\0';
    }

    // translate remainder
    for (j = 0; j < 4; ++j) {
        // find translation char in `b64_table'
        for (l = 0; l < 64; ++l) {
          if (tmp[j] == b64_table[l]) {
            tmp[j] = l;
            break;
          }
        }
    }

    // decode remainder
    buf[0] = (tmp[0] << 2) + ((tmp[1] & 0x30) >> 4);
    buf[1] = ((tmp[1] & 0xf) << 4) + ((tmp[2] & 0x3c) >> 2);
    buf[2] = ((tmp[2] & 0x3) << 6) + tmp[3];

    // write remainer decoded buffer to `dec'
    dec = (unsigned char *) b64_realloc(dec, size + (i - 1));
    if (dec != NULL){
      for (j = 0; (j < i - 1); ++j) {
        dec[size++] = buf[j];
      }
    } else {
      return NULL;
    }
  }

  // Make sure we have enough space to add '\0' character at end.
  dec = (unsigned char *) b64_realloc(dec, size + 1);
  if (dec != NULL){
    dec[size] = '\0';
  } else {
    return NULL;
  }

  // Return back the size of decoded string if demanded.
  if (decsize != NULL) {
    *decsize = size;
  }

  return dec;
}

unsigned char *
b64_decode (const char *src, size_t len) {
  return b64_decode_ex(src, len, NULL);
}


int hsitx2_otu(char *queryString,unsigned char *key_string, unsigned char *iv_string)
{

	int i=0;
	char *limitTime;
	int flag=0;


	AES_KEY enc_key, dec_key;
	unsigned char key[]="1q2w3e4r5t6y7u89";
	unsigned char iv[]="azsxdcfvgbhnjmkl";
			
	unsigned char dec_out[51];

	unsigned char *b64_dec=b64_decode(queryString,strlen(queryString));
/*
        memset(key, 0x00, AES_BLOCK_SIZE);
        for(i=0;i < AES_BLOCK_SIZE;i++)
        {
                key[i]=key_string[i];
        }

        memset(iv, 0x00, AES_BLOCK_SIZE);
        for(i=0;i < AES_BLOCK_SIZE;i++)
        {
                iv[i]=iv_string[i];
        }

*/
        memset(dec_out, 0x00, 51);
	AES_set_decrypt_key(key, 128, &dec_key); // Size of key is in bits
	AES_cbc_encrypt(b64_dec, dec_out, 50, &dec_key, iv, AES_DECRYPT);

	printf("Decrypred : %s(%ld)\n",dec_out,strlen(dec_out));

	
	return 0;
}


int main(int argc, char *argv[])  

{
        int error;
	int ret=0;
	char *result;


	printf("data : %s\n",argv[1]);

	ret=hsitx2_otu(argv[1],"1q2w3e4r5t6y7u89","azsxdcfvgbhnjmkl");

	if(ret<0)
	{
//		printf("Invaild URL\n");
		return -2;
	}
	return 0;
}
