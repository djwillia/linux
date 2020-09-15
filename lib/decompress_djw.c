// SPDX-License-Identifier: GPL-2.0-only
/*
 * Wrapper for decompressing LZ4-compressed kernel, initramfs, and initrd
 *
 * Copyright (C) 2013, LG Electronics, Kyungsik Lee <kyungsik.lee@lge.com>
 */

#ifdef STATIC
#define PREBOOT
#else
#endif
#include <linux/types.h>
#include <linux/decompress/mm.h>
#include <linux/compiler.h>

#include <asm/unaligned.h>

STATIC inline int INIT undjw(u8 *input, long in_len,
				long (*fill)(void *, unsigned long),
				long (*flush)(void *, unsigned long),
				u8 *output, long *posp,
				void (*error) (char *x))
{
    memcpy(output, input, in_len);
    return 0;
}

#ifdef PREBOOT
STATIC int INIT __decompress(unsigned char *buf, long in_len,
			      long (*fill)(void*, unsigned long),
			      long (*flush)(void*, unsigned long),
			      unsigned char *output, long out_len,
			      long *posp,
			      void (*error)(char *x)
	)
{
    //    if (in_len > out_len)
    //    error("DJW: input_len > output_len");

    return undjw(buf, in_len, fill, flush, output, posp, error);
}
#endif
