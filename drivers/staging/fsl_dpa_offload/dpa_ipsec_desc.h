/* Copyright 2008-2012 Freescale Semiconductor, Inc.
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

#ifndef _DPA_IPSEC_DESC_H_
#define _DPA_IPSEC_DESC_H_

#include "pdb.h"
#include "dpa_ipsec.h"
#include "desc_constr.h"

#define DPA_IPSEC_STATS_LEN	2	/* length in words */
#define MAX_CAAM_SHARED_DESCSIZE 50	/* If CAAM used with QI the maximum
					 * shared descriptor length is 50 words
					 */

struct desc_hdr {
	uint32_t hdr_word;
	union {
		struct ipsec_encap_pdb pdb_en;
		struct ipsec_decap_pdb pdb_dec;
	};
};

struct sec_descriptor {
	u64	preheader;
	/* SEC Shared Descriptor */
	union {
		uint32_t desc[MAX_CAAM_DESCSIZE];
		struct desc_hdr desc_hdr;
#define hdr_word	desc_hdr.hdr_word
#define pdb_en		desc_hdr.pdb_en
#define pdb_dec		desc_hdr.pdb_dec
	};
};

int get_sec_info(struct dpa_ipsec *dpa_ipsec);
int create_sec_descriptor(struct dpa_ipsec_sa *sa);
int generate_split_key(struct auth_params *auth_param);
int build_rjob_desc_ars_update(struct dpa_ipsec_sa *sa, enum dpa_ipsec_arw arw,
			       u32 msg_len);
int build_rjob_desc_seq_read(struct dpa_ipsec_sa *sa, u32 msg_len);
int build_rjob_desc_seq_write(struct dpa_ipsec_sa *sa, u32 msg_len);

#endif	/* _DPA_IPSEC_DESC_H_ */
