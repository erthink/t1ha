#ifdef _MSC_VER
#pragma warning(disable : 4464) /* relative include path contains '..' */
#endif

#define T1HA_IA32AES_NAME t1ha0_ia32aes_noavx_a
#include "../src/t1ha0_ia32aes_a.h"

#define T1HA_IA32AES_NAME t1ha0_ia32aes_noavx_b
#include "../src/t1ha0_ia32aes_b.h"
