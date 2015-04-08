/* Copyright 2014 Freescale Semiconductor Inc.
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
#ifndef __FSL_DPAA_FD_H
#define __FSL_DPAA_FD_H

/* Place-holder for FDs, we represent it via the simplest form that we need for
 * now. Different overlays may be needed to support different options, etc. (It
 * is impractical to define One True Struct, because the resulting encoding
 * routines (lots of read-modify-writes) would be worst-case performance whether
 * or not circumstances required them.) */
struct dpaa_fd {
	union {
		u32 words[8];
		struct dpaa_fd_simple {
			u32 addr_lo;
			u32 addr_hi;
			u32 len;
			/* offset in the MS 16 bits, BPID in the LS 16 bits */
			u32 bpid_offset;
			u32 frc; /* frame context */
			/* "err", "va", "cbmt", "asal", [...] */
			u32 ctrl;
			/* flow context */
			u32 flc_lo;
			u32 flc_hi;
		} simple;
	};
};

enum dpaa_fd_format {
	dpaa_fd_single = 0,
	dpaa_fd_list,
	dpaa_fd_sg
};

static inline dma_addr_t ldpaa_fd_get_addr(const struct dpaa_fd *fd)
{
	return (dma_addr_t)((((uint64_t)fd->simple.addr_hi) << 32)
				+ fd->simple.addr_lo);
}

static inline void ldpaa_fd_set_addr(struct dpaa_fd *fd, dma_addr_t addr)
{
	fd->simple.addr_hi = upper_32_bits(addr);
	fd->simple.addr_lo = lower_32_bits(addr);
}

static inline u32 ldpaa_fd_get_len(const struct dpaa_fd *fd)
{
	return fd->simple.len;
}

static inline void ldpaa_fd_set_len(struct dpaa_fd *fd, u32 len)
{
	fd->simple.len = len;
}

static inline uint16_t ldpaa_fd_get_offset(const struct dpaa_fd *fd)
{
	return (uint16_t)(fd->simple.bpid_offset >> 16) & 0x0FFF;
}

static inline void ldpaa_fd_set_offset(struct dpaa_fd *fd, uint16_t offset)
{
	fd->simple.bpid_offset &= 0xF000FFFF;
	fd->simple.bpid_offset |= (u32)offset << 16;
}

static inline enum dpaa_fd_format ldpaa_fd_get_format(const struct dpaa_fd *fd)
{
	return (enum dpaa_fd_format)((fd->simple.bpid_offset >> 28) & 0x3);
}

static inline void ldpaa_fd_set_format(struct dpaa_fd *fd,
				       enum dpaa_fd_format format)
{
	fd->simple.bpid_offset &= 0xCFFFFFFF;
	fd->simple.bpid_offset |= (u32)format << 28;
}

static inline uint16_t ldpaa_fd_get_bpid(const struct dpaa_fd *fd)
{
	return (uint16_t)(fd->simple.bpid_offset & 0xFFFF);
}

static inline void ldpaa_fd_set_bpid(struct dpaa_fd *fd, uint16_t bpid)
{
	fd->simple.bpid_offset &= 0xFFFF0000;
	fd->simple.bpid_offset |= (u32)bpid;
}

struct dpaa_sg_entry {
	u32 addr_lo;
	u32 addr_hi;
	u32 len;
	u32 bpid_offset;
};

enum dpaa_sg_format {
	dpaa_sg_single = 0,
	dpaa_sg_frame_data,
	dpaa_sg_sgt_ext
};

static inline dma_addr_t ldpaa_sg_get_addr(const struct dpaa_sg_entry *sg)
{
	return (dma_addr_t)((((u64)sg->addr_hi) << 32) + sg->addr_lo);
}

static inline void ldpaa_sg_set_addr(struct dpaa_sg_entry *sg, dma_addr_t addr)
{
	sg->addr_hi = upper_32_bits(addr);
	sg->addr_lo = lower_32_bits(addr);
}


static inline bool ldpaa_sg_short_len(const struct dpaa_sg_entry *sg)
{
	return (sg->bpid_offset >> 30) & 0x1;
}

static inline u32 ldpaa_sg_get_len(const struct dpaa_sg_entry *sg)
{
	if (ldpaa_sg_short_len(sg))
		return sg->len & 0x1FFFF;
	return sg->len;
}

static inline void ldpaa_sg_set_len(struct dpaa_sg_entry *sg, u32 len)
{
	sg->len = len;
}

static inline u16 ldpaa_sg_get_offset(const struct dpaa_sg_entry *sg)
{
	return (u16)(sg->bpid_offset >> 16) & 0x0FFF;
}

static inline void ldpaa_sg_set_offset(struct dpaa_sg_entry *sg,
				       u16 offset)
{
	sg->bpid_offset &= 0xF000FFFF;
	sg->bpid_offset |= (u32)offset << 16;
}

static inline enum dpaa_sg_format
	ldpaa_sg_get_format(const struct dpaa_sg_entry *sg)
{
	return (enum dpaa_sg_format)((sg->bpid_offset >> 28) & 0x3);
}

static inline void ldpaa_sg_set_format(struct dpaa_sg_entry *sg,
				       enum dpaa_sg_format format)
{
	sg->bpid_offset &= 0xCFFFFFFF;
	sg->bpid_offset |= (u32)format << 28;
}

static inline u16 ldpaa_sg_get_bpid(const struct dpaa_sg_entry *sg)
{
	return (u16)(sg->bpid_offset & 0x3FFF);
}

static inline void ldpaa_sg_set_bpid(struct dpaa_sg_entry *sg, u16 bpid)
{
	sg->bpid_offset &= 0xFFFFC000;
	sg->bpid_offset |= (u32)bpid;
}

static inline bool ldpaa_sg_is_final(const struct dpaa_sg_entry *sg)
{
	return !!(sg->bpid_offset >> 31);
}

static inline void ldpaa_sg_set_final(struct dpaa_sg_entry *sg, bool final)
{
	sg->bpid_offset &= 0x7FFFFFFF;
	sg->bpid_offset |= (u32)final << 31;
}

/* When frames are dequeued, the FDs show up inside "dequeue" result structures
 * (if at all, not all dequeue results contain valid FDs). This structure type
 * is intentionally defined without internal detail, and the only reason it
 * isn't declared opaquely (without size) is to allow the user to provide
 * suitably-sized (and aligned) memory for these entries. */
struct ldpaa_dq {
	uint32_t dont_manipulate_directly[16];
};

/* Parsing frame dequeue results */
#define LDPAA_DQ_STAT_FQEMPTY       0x80
#define LDPAA_DQ_STAT_HELDACTIVE    0x40
#define LDPAA_DQ_STAT_FORCEELIGIBLE 0x20
#define LDPAA_DQ_STAT_VALIDFRAME    0x10
#define LDPAA_DQ_STAT_ODPVALID      0x04
#define LDPAA_DQ_STAT_VOLATILE      0x02
#define LDPAA_DQ_STAT_EXPIRED       0x01
uint32_t ldpaa_dq_flags(const struct ldpaa_dq *);
static inline int ldpaa_dq_is_pull(const struct ldpaa_dq *dq)
{
	return (int)(ldpaa_dq_flags(dq) & LDPAA_DQ_STAT_VOLATILE);
}
static inline int ldpaa_dq_is_pull_complete(
					const struct ldpaa_dq *dq)
{
	return (int)(ldpaa_dq_flags(dq) & LDPAA_DQ_STAT_EXPIRED);
}
/* seqnum/odpid are valid only if VALIDFRAME and ODPVALID flags are TRUE */
uint16_t ldpaa_dq_seqnum(const struct ldpaa_dq *);
uint16_t ldpaa_dq_odpid(const struct ldpaa_dq *);
uint32_t ldpaa_dq_fqid(const struct ldpaa_dq *);
uint32_t ldpaa_dq_byte_count(const struct ldpaa_dq *);
uint32_t ldpaa_dq_frame_count(const struct ldpaa_dq *);
uint32_t ldpaa_dq_fqd_ctx_hi(const struct ldpaa_dq *);
uint32_t ldpaa_dq_fqd_ctx_lo(const struct ldpaa_dq *);
/* get the Frame Descriptor */
const struct dpaa_fd *ldpaa_dq_fd(const struct ldpaa_dq *);

#endif /* __FSL_DPAA_FD_H */
