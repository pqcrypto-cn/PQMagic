#ifndef _SM_INTERFACE_H_
#define _SM_INTERFACE_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned long long	u8;
typedef unsigned int		u4;
typedef unsigned short		u2;
typedef unsigned char		u1;

// All in bytes
#define SM3_BLOCK_SIZE      64
#define SM3_DIGEST_LENGTH	32
#define SM3_HMAC_SIZE	    32
#define SM3_CBLOCK	        (SM3_BLOCK_SIZE)

#endif
// end of SM interface definitions
