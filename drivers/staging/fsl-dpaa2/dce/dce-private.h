/* Copyright (C) 2014 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#ifndef __DCE_PRIVATE_H
#define __DCE_PRIVATE_H

#include "dce-sys-decl.h"

/* Perform extra checking */
#define DCE_CHECKING
#define MAKE_MASK32(width) (width == 32 ? 0xffffffff : \
				 (u32)((1 << width) - 1))
#define DECLARE_CODEC32(t) \
static inline u32 e32_##t(u32 lsoffset, u32 width, t val) \
{ \
	BUG_ON(width > (sizeof(t) * 8)); \
	return ((u32)val & MAKE_MASK32(width)) << lsoffset; \
} \
static inline t d32_##t(u32 lsoffset, u32 width, u32 val) \
{ \
	BUG_ON(width > (sizeof(t) * 8)); \
	return (t)((val >> lsoffset) & MAKE_MASK32(width)); \
} \
static inline u32 i32_##t(u32 lsoffset, u32 width, \
				u32 val) \
{ \
	BUG_ON(width > (sizeof(t) * 8)); \
	return e32_##t(lsoffset, width, d32_##t(lsoffset, width, val)); \
} \
static inline u32 r32_##t(u32 lsoffset, u32 width, \
				u32 val) \
{ \
	BUG_ON(width > (sizeof(t) * 8)); \
	return ~(MAKE_MASK32(width) << lsoffset) & val; \
}
DECLARE_CODEC32(u32)
DECLARE_CODEC32(uint16_t)
DECLARE_CODEC32(uint8_t)
DECLARE_CODEC32(int)
	/*********************/
	/* Debugging assists */
	/*********************/

static inline void __hexdump(unsigned long start, unsigned long end,
			unsigned long p, size_t sz, const unsigned char *c)
{
	while (start < end) {
		unsigned int pos = 0;
		char buf[64];
		int nl = 0;

		pos += sprintf(buf + pos, "%08lx: ", start);
		do {
			if ((start < p) || (start >= (p + sz)))
				pos += sprintf(buf + pos, "..");
			else
				pos += sprintf(buf + pos, "%02x", *(c++));
			if (!(++start & 15)) {
				buf[pos++] = '\n';
				nl = 1;
			} else {
				nl = 0;
				if (!(start & 1))
					buf[pos++] = ' ';
				if (!(start & 3))
					buf[pos++] = ' ';
			}
		} while (start & 15);
		if (!nl)
			buf[pos++] = '\n';
		buf[pos] = '\0';
		pr_info("%s", buf);
	}
}
static inline void hexdump(const void *ptr, size_t sz)
{
	unsigned long p = (unsigned long)ptr;
	unsigned long start = p & ~(unsigned long)15;
	unsigned long end = (p + sz + 15) & ~(unsigned long)15;
	const unsigned char *c = ptr;

	__hexdump(start, end, p, sz, c);
}

#endif /* DCE_PRIVATE_H */
