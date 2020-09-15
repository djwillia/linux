/* SPDX-License-Identifier: GPL-2.0 */
#ifndef DECOMPRESS_UNDJW_H
#define DECOMPRESS_UNDJW_H

int undjw(unsigned char *inbuf, long len,
	long (*fill)(void*, unsigned long),
	long (*flush)(void*, unsigned long),
	unsigned char *output,
	long *pos,
	void(*error)(char *x));
#endif
