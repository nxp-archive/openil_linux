/**
 * Copyright 2014 Freescale Semiconductor Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *	 names of its contributors may be used to endorse or promote products
 *	 derived from this software without specific prior written permission.
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

#include <net/hw_distribution.h>

static t_LnxWrpFmDev *get_FmDev_from_FmPortDev(t_LnxWrpFmPortDev *p_FmPortDev)
{
	t_LnxWrpFmDev *p_LnxWrpFmDev;

	p_LnxWrpFmDev = (t_LnxWrpFmDev *)p_FmPortDev->h_LnxWrpFmDev;
	return p_LnxWrpFmDev;
}

static t_LnxWrpFmPortDev *get_FmPortDev_from_fm_port(struct fm_port *fm_port)
{
	t_LnxWrpFmPortDev *p_LnxWrpFmPortDev;

	p_LnxWrpFmPortDev = (t_LnxWrpFmPortDev *)fm_port;
	return p_LnxWrpFmPortDev;
}

/* for: FM_PORT_Disable/FM_PORT_Enable/FM_PORT_SetPCD
 * (t_Handle h_FmPort,...)
 */
static t_Handle get_h_FmPort_from_fm_port(struct fm_port *fm_port)
{
	t_LnxWrpFmPortDev *p_LnxWrpFmPortDev =
		get_FmPortDev_from_fm_port(fm_port);
	return p_LnxWrpFmPortDev->h_Dev;
}

/* for: FM_PCD_Enable/FM_PCD_NetEnvCharacteristicsSet/
 * FM_PCD_KgSchemeSet(t_Handle h_FmPcd)
 */
static t_Handle get_h_FmPcd_from_fm_port(struct fm_port *fm_port)
{
	t_LnxWrpFmPortDev *p_LnxWrpFmPortDev;
	t_LnxWrpFmDev *p_LnxWrpFmDev;
	t_Handle h_FmPcd;

	p_LnxWrpFmPortDev = get_FmPortDev_from_fm_port(fm_port);
	p_LnxWrpFmDev = get_FmDev_from_FmPortDev(p_LnxWrpFmPortDev);
	h_FmPcd = p_LnxWrpFmDev->h_PcdDev;
	return h_FmPcd;
}

static int alloc_pcd_mem(struct fm_port *fm_port, uint8_t numOfSchemes,
			 u32 pcd_fqids_base, uint8_t distNumOfQueues,
			 struct bonding *bond)
{
	t_Handle h_FmPcd;
	t_Handle h_FmPort;
	t_Handle h_NetEnv;

	t_FmPcdNetEnvParams *netEnvParams;
	t_FmPcdKgSchemeParams *scheme;
	t_FmPortPcdParams *pcdParam;
	t_FmPortPcdPrsParams *prsParam;
	t_FmPortPcdKgParams *kgParam;
	/* reuse below "ea_xxx_yyy" variables, can reduce 120 lines of codes */
	t_FmPcdExtractEntry ea_eth_sa, ea_eth_da, ea_ipv4_sa, ea_ipv4_da,
			    ea_ipv6_sa, ea_ipv6_da, ea_tcp_sp, ea_tcp_dp,
			    ea_udp_sp, ea_udp_dp, ea_nexthdr, ea_nextp;

	if (bond->params.ohp->h_FmPcd)
		return BOND_OH_SUCCESS;

	/* get handle of fm_port/fm_pcd from kernel struct */
	h_FmPort = get_h_FmPort_from_fm_port(fm_port);
	if (!h_FmPort) {
		pr_err("error on get_h_FmPort_from_fm_port.\n");
		return E_INVALID_VALUE;
	}
	h_FmPcd = get_h_FmPcd_from_fm_port(fm_port);
	if (!h_FmPcd) {
		pr_err("error on get_h_FmPcd_from_fm_port.\n");
		return E_INVALID_VALUE;
	}
	/* set net env, get handle of net env */
	netEnvParams = kzalloc(sizeof(t_FmPcdNetEnvParams), GFP_KERNEL);
	if (!netEnvParams) {
		pr_err("Failed to allocate netEnvParams.\n");
		return -ENOMEM;
	}
	hw_lag_dbg("netEnvParams:%p\n", netEnvParams);
	netEnvParams->numOfDistinctionUnits = 5;
	netEnvParams->units[0].hdrs[0].hdr = HEADER_TYPE_ETH;
	netEnvParams->units[1].hdrs[0].hdr = HEADER_TYPE_IPv4;
	netEnvParams->units[2].hdrs[0].hdr = HEADER_TYPE_IPv6;
	netEnvParams->units[3].hdrs[0].hdr = HEADER_TYPE_TCP;
	netEnvParams->units[4].hdrs[0].hdr = HEADER_TYPE_UDP;

	FM_PCD_Enable(h_FmPcd);
	h_NetEnv = FM_PCD_NetEnvCharacteristicsSet(h_FmPcd, netEnvParams);
	if (!h_NetEnv) {
		pr_err("error on FM_PCD_NetEnvCharacteristicsSet.\n");
		goto netEnvParams_err;
	}
	hw_lag_dbg("FM_PCD_NetEnvCharacteristicsSet() ok.\n");
	/* bind port to PCD properties */
	/* initialize PCD parameters */
	pcdParam = kzalloc(sizeof(t_FmPortPcdParams), GFP_KERNEL);
	if (!pcdParam) {
		pr_err("Failed to allocate pcdParam.\n");
		goto netEnvParams_err;
	}
	hw_lag_dbg("pcdParam:%p\n", pcdParam);
	/* initialize parser port parameters */
	prsParam = kzalloc(sizeof(t_FmPortPcdPrsParams), GFP_KERNEL);
	if (!prsParam) {
		pr_err("Failed to allocate prsParam.\n");
		goto pcdParam_err;
	}

	hw_lag_dbg("prsParam:%p\n", prsParam);
	prsParam->parsingOffset = 0;
	prsParam->firstPrsHdr = HEADER_TYPE_ETH;
	pcdParam->h_NetEnv = h_NetEnv;
	pcdParam->pcdSupport = e_FM_PORT_PCD_SUPPORT_PRS_AND_KG;
	pcdParam->p_PrsParams = prsParam;

	/* initialize Keygen port parameters */
	kgParam = kzalloc(sizeof(t_FmPortPcdKgParams), GFP_KERNEL);
	if (!kgParam) {
		pr_err("Failed to allocate kgParam.\n");
		goto prsParam_err;
	}

	hw_lag_dbg("kgParam:%p\n", kgParam);
	kgParam->numOfSchemes = numOfSchemes;
	kgParam->directScheme = FALSE;

	pcdParam->p_KgParams = kgParam;

	/* initialize schemes according to numOfSchemes */
	scheme = kzalloc(sizeof(t_FmPcdKgSchemeParams) * MAX_SCHEMES,
			 GFP_KERNEL);
	if (!scheme) {
		pr_err("Failed to allocate scheme.\n");
		goto kgParam_err;
	}

	hw_lag_dbg("scheme:%p\n", scheme);
	/* Distribution: according to Layer2 info MAC */
	scheme[L2_MAC].alwaysDirect = 0;
	scheme[L2_MAC].netEnvParams.numOfDistinctionUnits = 1;
	scheme[L2_MAC].netEnvParams.unitIds[0] = 0;
	scheme[L2_MAC].useHash = 1;
	scheme[L2_MAC].baseFqid = pcd_fqids_base;
	scheme[L2_MAC].nextEngine = e_FM_PCD_DONE;
	scheme[L2_MAC].schemeCounter.update = 1;
	scheme[L2_MAC].schemeCounter.value = 0;
	scheme[L2_MAC].keyExtractAndHashParams.numOfUsedMasks = 0;
	scheme[L2_MAC].keyExtractAndHashParams.hashShift = 0;
	scheme[L2_MAC].keyExtractAndHashParams.symmetricHash = 0;
	scheme[L2_MAC].keyExtractAndHashParams.hashDistributionNumOfFqids =
		distNumOfQueues;
	scheme[L2_MAC].keyExtractAndHashParams.numOfUsedExtracts = 2;
	scheme[L2_MAC].numOfUsedExtractedOrs = 0;
	scheme[L2_MAC].netEnvParams.h_NetEnv = h_NetEnv;
	scheme[L2_MAC].id.relativeSchemeId = L2_MAC;

	/* Extract field:ethernet.src */
	memset(&ea_eth_sa, 0, sizeof(t_FmPcdExtractEntry));
	ea_eth_sa.type = e_FM_PCD_EXTRACT_BY_HDR;
	ea_eth_sa.extractByHdr.hdr = HEADER_TYPE_ETH;
	ea_eth_sa.extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
	ea_eth_sa.extractByHdr.ignoreProtocolValidation = 0;
	ea_eth_sa.extractByHdr.type = e_FM_PCD_EXTRACT_FULL_FIELD;
	ea_eth_sa.extractByHdr.extractByHdrType.fullField.eth =
		NET_HEADER_FIELD_ETH_SA;
	scheme[L2_MAC].keyExtractAndHashParams.extractArray[0] =
		ea_eth_sa;

       /* Extract field:ethernet.dst */
	memset(&ea_eth_da, 0, sizeof(t_FmPcdExtractEntry));
	ea_eth_da.type = e_FM_PCD_EXTRACT_BY_HDR;
	ea_eth_da.extractByHdr.hdr = HEADER_TYPE_ETH;
	ea_eth_da.extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
	ea_eth_da.extractByHdr.ignoreProtocolValidation = 0;
	ea_eth_da.extractByHdr.type = e_FM_PCD_EXTRACT_FULL_FIELD;
	ea_eth_da.extractByHdr.extractByHdrType.fullField.eth =
		NET_HEADER_FIELD_ETH_DA;
	scheme[L2_MAC].keyExtractAndHashParams.extractArray[1] =
		ea_eth_da;

	/* Distribution: Layer2 and Layer3 info, MAC and ipv6 */
	scheme[MAC_L3_IPV6].alwaysDirect = 0;
	scheme[MAC_L3_IPV6].netEnvParams.numOfDistinctionUnits = 2;
	scheme[MAC_L3_IPV6].netEnvParams.unitIds[0] = 0;
	scheme[MAC_L3_IPV6].netEnvParams.unitIds[1] = 2;
	scheme[MAC_L3_IPV6].useHash = 1;
	scheme[MAC_L3_IPV6].baseFqid = pcd_fqids_base;
	scheme[MAC_L3_IPV6].nextEngine = e_FM_PCD_DONE;
	scheme[MAC_L3_IPV6].schemeCounter.update = 1;
	scheme[MAC_L3_IPV6].schemeCounter.value = 0;
	scheme[MAC_L3_IPV6].keyExtractAndHashParams.numOfUsedMasks = 0;
	scheme[MAC_L3_IPV6].keyExtractAndHashParams.hashShift = 0;
	scheme[MAC_L3_IPV6].keyExtractAndHashParams.symmetricHash = 0;
	scheme[MAC_L3_IPV6].keyExtractAndHashParams.hashDistributionNumOfFqids =
		distNumOfQueues;
	scheme[MAC_L3_IPV6].keyExtractAndHashParams.numOfUsedExtracts = 4;
	scheme[MAC_L3_IPV6].numOfUsedExtractedOrs = 0;
	scheme[MAC_L3_IPV6].netEnvParams.h_NetEnv = h_NetEnv;
	scheme[MAC_L3_IPV6].id.relativeSchemeId = MAC_L3_IPV6;
	/* Extract field:ethernet.src */
	scheme[MAC_L3_IPV6].keyExtractAndHashParams.extractArray[0] =
		ea_eth_sa;
	/* Extract field:ethernet.dst */
	scheme[MAC_L3_IPV6].keyExtractAndHashParams.extractArray[1] =
		ea_eth_da;

	/* Extract field:ipv6.src */
	memset(&ea_ipv6_sa, 0, sizeof(t_FmPcdExtractEntry));
	ea_ipv6_sa.type = e_FM_PCD_EXTRACT_BY_HDR;
	ea_ipv6_sa.extractByHdr.hdr = HEADER_TYPE_IPv6;
	ea_ipv6_sa.extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
	ea_ipv6_sa.extractByHdr.ignoreProtocolValidation = 0;
	ea_ipv6_sa.extractByHdr.type = e_FM_PCD_EXTRACT_FULL_FIELD;
	ea_ipv6_sa.extractByHdr.extractByHdrType.fullField.ipv6 =
		NET_HEADER_FIELD_IPv6_SRC_IP;
	scheme[MAC_L3_IPV6].keyExtractAndHashParams.extractArray[2] =
		ea_ipv6_sa;

	/* Extract field:ipv6.dst */
	memset(&ea_ipv6_da, 0, sizeof(t_FmPcdExtractEntry));
	ea_ipv6_da.type = e_FM_PCD_EXTRACT_BY_HDR;
	ea_ipv6_da.extractByHdr.hdr = HEADER_TYPE_IPv6;
	ea_ipv6_da.extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
	ea_ipv6_da.extractByHdr.ignoreProtocolValidation = 0;
	ea_ipv6_da.extractByHdr.type = e_FM_PCD_EXTRACT_FULL_FIELD;
	ea_ipv6_da.extractByHdr.extractByHdrType.fullField.ipv6 =
		NET_HEADER_FIELD_IPv6_DST_IP;
	scheme[MAC_L3_IPV6].keyExtractAndHashParams.extractArray[3] =
		ea_ipv6_da;

	/* Distribution: Layer2 and Layer3 info, MAC ipv4 */
	scheme[MAC_L3_IPV4].alwaysDirect = 0;
	scheme[MAC_L3_IPV4].netEnvParams.numOfDistinctionUnits = 2;
	scheme[MAC_L3_IPV4].netEnvParams.unitIds[0] = 0;
	scheme[MAC_L3_IPV4].netEnvParams.unitIds[1] = 1;
	scheme[MAC_L3_IPV4].useHash = 1;
	scheme[MAC_L3_IPV4].baseFqid = pcd_fqids_base;
	scheme[MAC_L3_IPV4].nextEngine = e_FM_PCD_DONE;
	scheme[MAC_L3_IPV4].schemeCounter.update = 1;
	scheme[MAC_L3_IPV4].schemeCounter.value = 0;
	scheme[MAC_L3_IPV4].keyExtractAndHashParams.numOfUsedMasks = 0;
	scheme[MAC_L3_IPV4].keyExtractAndHashParams.hashShift = 0;
	scheme[MAC_L3_IPV4].keyExtractAndHashParams.symmetricHash = 0;
	scheme[MAC_L3_IPV4].keyExtractAndHashParams.hashDistributionNumOfFqids =
		distNumOfQueues;
	scheme[MAC_L3_IPV4].keyExtractAndHashParams.numOfUsedExtracts = 4;
	scheme[MAC_L3_IPV4].numOfUsedExtractedOrs = 0;
	scheme[MAC_L3_IPV4].netEnvParams.h_NetEnv = h_NetEnv;
	scheme[MAC_L3_IPV4].id.relativeSchemeId = MAC_L3_IPV4;
	/* Extract field:ethernet.src */
	scheme[MAC_L3_IPV4].keyExtractAndHashParams.extractArray[0] =
		ea_eth_sa;
	/* Extract field:ethernet.dst */
	scheme[MAC_L3_IPV4].keyExtractAndHashParams.extractArray[1] =
		ea_eth_da;
	/* Extract field:ipv4.src */
	memset(&ea_ipv4_sa, 0, sizeof(t_FmPcdExtractEntry));
	ea_ipv4_sa.type = e_FM_PCD_EXTRACT_BY_HDR;
	ea_ipv4_sa.extractByHdr.hdr = HEADER_TYPE_IPv4;
	ea_ipv4_sa.extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
	ea_ipv4_sa.extractByHdr.ignoreProtocolValidation = 0;
	ea_ipv4_sa.extractByHdr.type = e_FM_PCD_EXTRACT_FULL_FIELD;
	ea_ipv4_sa.extractByHdr.extractByHdrType.fullField.ipv4 =
		NET_HEADER_FIELD_IPv4_SRC_IP;
	scheme[MAC_L3_IPV4].keyExtractAndHashParams.extractArray[2] =
		ea_ipv4_sa;
	/* Extract field:ipv4.dst */
	memset(&ea_ipv4_da, 0, sizeof(t_FmPcdExtractEntry));
	ea_ipv4_da.type = e_FM_PCD_EXTRACT_BY_HDR;
	ea_ipv4_da.extractByHdr.hdr = HEADER_TYPE_IPv4;
	ea_ipv4_da.extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
	ea_ipv4_da.extractByHdr.ignoreProtocolValidation = 0;
	ea_ipv4_da.extractByHdr.type = e_FM_PCD_EXTRACT_FULL_FIELD;
	ea_ipv4_da.extractByHdr.extractByHdrType.fullField.ipv4 =
		NET_HEADER_FIELD_IPv4_DST_IP;
	scheme[MAC_L3_IPV4].keyExtractAndHashParams.extractArray[3] =
		ea_ipv4_da;

	/* Distribution: Layer234 info MAC ipv6 tcp */
	scheme[MAC_IPV6_TCP].alwaysDirect = 0;
	scheme[MAC_IPV6_TCP].netEnvParams.numOfDistinctionUnits = 3;
	scheme[MAC_IPV6_TCP].netEnvParams.unitIds[0] = 0;
	scheme[MAC_IPV6_TCP].netEnvParams.unitIds[1] = 2;
	scheme[MAC_IPV6_TCP].netEnvParams.unitIds[2] = 3;
	scheme[MAC_IPV6_TCP].useHash = 1;
	scheme[MAC_IPV6_TCP].baseFqid = pcd_fqids_base;
	scheme[MAC_IPV6_TCP].nextEngine = e_FM_PCD_DONE;
	scheme[MAC_IPV6_TCP].schemeCounter.update = 1;
	scheme[MAC_IPV6_TCP].schemeCounter.value = 0;
	scheme[MAC_IPV6_TCP].keyExtractAndHashParams.numOfUsedMasks = 0;
	scheme[MAC_IPV6_TCP].keyExtractAndHashParams.hashShift = 0;
	scheme[MAC_IPV6_TCP].keyExtractAndHashParams.symmetricHash = 0;
	scheme[MAC_IPV6_TCP].keyExtractAndHashParams.hashDistributionNumOfFqids
		= distNumOfQueues;
	scheme[MAC_IPV6_TCP].keyExtractAndHashParams.numOfUsedExtracts = 7;
	scheme[MAC_IPV6_TCP].numOfUsedExtractedOrs = 0;
	scheme[MAC_IPV6_TCP].netEnvParams.h_NetEnv = h_NetEnv;
	scheme[MAC_IPV6_TCP].id.relativeSchemeId = MAC_IPV6_TCP;
	/* Extract field:ethernet.src */
	scheme[MAC_IPV6_TCP].keyExtractAndHashParams.extractArray[0] =
		ea_eth_sa;
	/* Extract field:ethernet.dst */
	scheme[MAC_IPV6_TCP].keyExtractAndHashParams.extractArray[1] =
		ea_eth_da;
	/* Extract field:ipv6.src */
	scheme[MAC_IPV6_TCP].keyExtractAndHashParams.extractArray[2] =
		ea_ipv6_sa;
	/* Extract field:ipv6.dst */
	scheme[MAC_IPV6_TCP].keyExtractAndHashParams.extractArray[3] =
		ea_ipv6_da;

	/* Extract field:ipv6.nexthdr */
	memset(&ea_nexthdr, 0, sizeof(t_FmPcdExtractEntry));
	ea_nexthdr.type = e_FM_PCD_EXTRACT_BY_HDR;
	ea_nexthdr.extractByHdr.hdr = HEADER_TYPE_IPv6;
	ea_nexthdr.extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
	ea_nexthdr.extractByHdr.ignoreProtocolValidation = 0;
	ea_nexthdr.extractByHdr.type = e_FM_PCD_EXTRACT_FULL_FIELD;
	ea_nexthdr.extractByHdr.extractByHdrType.fullField.ipv6 =
		NET_HEADER_FIELD_IPv6_NEXT_HDR;
	scheme[MAC_IPV6_TCP].keyExtractAndHashParams.extractArray[4] =
		ea_nexthdr;
	/* Extract field:tcp.sport */
	memset(&ea_tcp_sp, 0, sizeof(t_FmPcdExtractEntry));
	ea_tcp_sp.type = e_FM_PCD_EXTRACT_BY_HDR;
	ea_tcp_sp.extractByHdr.hdr = HEADER_TYPE_TCP;
	ea_tcp_sp.extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
	ea_tcp_sp.extractByHdr.ignoreProtocolValidation = 0;
	ea_tcp_sp.extractByHdr.type = e_FM_PCD_EXTRACT_FULL_FIELD;
	ea_tcp_sp.extractByHdr.extractByHdrType.fullField.tcp =
		NET_HEADER_FIELD_TCP_PORT_SRC;
	scheme[MAC_IPV6_TCP].keyExtractAndHashParams.extractArray[5] =
		ea_tcp_sp;
	/* Extract field:tcp.dport */
	memset(&ea_tcp_dp, 0, sizeof(t_FmPcdExtractEntry));
	ea_tcp_dp.type = e_FM_PCD_EXTRACT_BY_HDR;
	ea_tcp_dp.extractByHdr.hdr = HEADER_TYPE_TCP;
	ea_tcp_dp.extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
	ea_tcp_dp.extractByHdr.ignoreProtocolValidation = 0;
	ea_tcp_dp.extractByHdr.type = e_FM_PCD_EXTRACT_FULL_FIELD;
	ea_tcp_dp.extractByHdr.extractByHdrType.fullField.tcp =
		NET_HEADER_FIELD_TCP_PORT_DST;
	scheme[MAC_IPV6_TCP].keyExtractAndHashParams.extractArray[6] =
		ea_tcp_dp;

	/* Distribution: Layer234 info MAC ipv6 udp */
	scheme[MAC_IPV6_UDP].alwaysDirect = 0;
	scheme[MAC_IPV6_UDP].netEnvParams.numOfDistinctionUnits = 3;
	scheme[MAC_IPV6_UDP].netEnvParams.unitIds[0] = 0;
	scheme[MAC_IPV6_UDP].netEnvParams.unitIds[1] = 2;
	scheme[MAC_IPV6_UDP].netEnvParams.unitIds[2] = 4;
	scheme[MAC_IPV6_UDP].useHash = 1;
	scheme[MAC_IPV6_UDP].baseFqid = pcd_fqids_base;
	scheme[MAC_IPV6_UDP].nextEngine = e_FM_PCD_DONE;
	scheme[MAC_IPV6_UDP].schemeCounter.update = 1;
	scheme[MAC_IPV6_UDP].schemeCounter.value = 0;
	scheme[MAC_IPV6_UDP].keyExtractAndHashParams.numOfUsedMasks = 0;
	scheme[MAC_IPV6_UDP].keyExtractAndHashParams.hashShift = 0;
	scheme[MAC_IPV6_UDP].keyExtractAndHashParams.symmetricHash = 0;
	scheme[MAC_IPV6_UDP].keyExtractAndHashParams.hashDistributionNumOfFqids
		= distNumOfQueues;
	scheme[MAC_IPV6_UDP].keyExtractAndHashParams.numOfUsedExtracts = 7;
	scheme[MAC_IPV6_UDP].numOfUsedExtractedOrs = 0;
	scheme[MAC_IPV6_UDP].netEnvParams.h_NetEnv = h_NetEnv;
	scheme[MAC_IPV6_UDP].id.relativeSchemeId = MAC_IPV6_UDP;
	/* Extract field:ethernet.src */
	scheme[MAC_IPV6_UDP].keyExtractAndHashParams.extractArray[0] =
		ea_eth_sa;
	/* Extract field:ethernet.dst */
	scheme[MAC_IPV6_UDP].keyExtractAndHashParams.extractArray[1] =
		ea_eth_da;
	/* Extract field:ipv6.src */
	scheme[MAC_IPV6_UDP].keyExtractAndHashParams.extractArray[2] =
		ea_ipv6_sa;
	/* Extract field:ipv6.dst */
	scheme[MAC_IPV6_UDP].keyExtractAndHashParams.extractArray[3] =
		ea_ipv6_da;
	/* Extract field:ipv6.nexthdr */
	scheme[MAC_IPV6_UDP].keyExtractAndHashParams.extractArray[4] =
		ea_nexthdr;
	/* Extract field:udp.sport */
	memset(&ea_udp_sp, 0, sizeof(t_FmPcdExtractEntry));
	ea_udp_sp.type = e_FM_PCD_EXTRACT_BY_HDR;
	ea_udp_sp.extractByHdr.hdr = HEADER_TYPE_UDP;
	ea_udp_sp.extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
	ea_udp_sp.extractByHdr.ignoreProtocolValidation = 0;
	ea_udp_sp.extractByHdr.type = e_FM_PCD_EXTRACT_FULL_FIELD;
	ea_udp_sp.extractByHdr.extractByHdrType.fullField.udp
		= NET_HEADER_FIELD_UDP_PORT_SRC;
	scheme[MAC_IPV6_UDP].keyExtractAndHashParams.extractArray[5] =
		ea_udp_sp;
	/* Extract field:udp.dport */
	memset(&ea_udp_dp, 0, sizeof(t_FmPcdExtractEntry));
	ea_udp_dp.type = e_FM_PCD_EXTRACT_BY_HDR;
	ea_udp_dp.extractByHdr.hdr = HEADER_TYPE_UDP;
	ea_udp_dp.extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
	ea_udp_dp.extractByHdr.ignoreProtocolValidation = 0;
	ea_udp_dp.extractByHdr.type = e_FM_PCD_EXTRACT_FULL_FIELD;
	ea_udp_dp.extractByHdr.extractByHdrType.fullField.udp
		= NET_HEADER_FIELD_UDP_PORT_DST;
	scheme[MAC_IPV6_UDP].keyExtractAndHashParams.extractArray[6] =
		ea_udp_dp;

	/* Distribution: Layer234 info MAC ipv4 tcp */
	scheme[MAC_IPV4_TCP].alwaysDirect = 0;
	scheme[MAC_IPV4_TCP].netEnvParams.numOfDistinctionUnits = 3;
	scheme[MAC_IPV4_TCP].netEnvParams.unitIds[0] = 0;
	scheme[MAC_IPV4_TCP].netEnvParams.unitIds[1] = 1;
	scheme[MAC_IPV4_TCP].netEnvParams.unitIds[2] = 3;
	scheme[MAC_IPV4_TCP].useHash = 1;
	scheme[MAC_IPV4_TCP].baseFqid = pcd_fqids_base;
	scheme[MAC_IPV4_TCP].nextEngine = e_FM_PCD_DONE;
	scheme[MAC_IPV4_TCP].schemeCounter.update = 1;
	scheme[MAC_IPV4_TCP].schemeCounter.value = 0;
	scheme[MAC_IPV4_TCP].keyExtractAndHashParams.numOfUsedMasks = 0;
	scheme[MAC_IPV4_TCP].keyExtractAndHashParams.hashShift = 0;
	scheme[MAC_IPV4_TCP].keyExtractAndHashParams.symmetricHash = 0;
	scheme[MAC_IPV4_TCP].keyExtractAndHashParams.hashDistributionNumOfFqids
		= distNumOfQueues;
	scheme[MAC_IPV4_TCP].keyExtractAndHashParams.numOfUsedExtracts = 7;
	scheme[MAC_IPV4_TCP].numOfUsedExtractedOrs = 0;
	scheme[MAC_IPV4_TCP].netEnvParams.h_NetEnv = h_NetEnv;
	scheme[MAC_IPV4_TCP].id.relativeSchemeId = MAC_IPV4_TCP;
	/* Extract field:ethernet.src */
	scheme[MAC_IPV4_TCP].keyExtractAndHashParams.extractArray[0] =
		ea_eth_sa;
	/* Extract field:ethernet.dst */
	scheme[MAC_IPV4_TCP].keyExtractAndHashParams.extractArray[1] =
		ea_eth_da;
	/* Extract field:ipv4.src */
	scheme[MAC_IPV4_TCP].keyExtractAndHashParams.extractArray[2] =
		ea_ipv4_sa;
	/* Extract field:ipv4.dst */
	scheme[MAC_IPV4_TCP].keyExtractAndHashParams.extractArray[3] =
		ea_ipv4_da;
	/* Extract field:ipv4.nextp */
	memset(&ea_nextp, 0, sizeof(t_FmPcdExtractEntry));
	ea_nextp.type = e_FM_PCD_EXTRACT_BY_HDR;
	ea_nextp.extractByHdr.hdr = HEADER_TYPE_IPv4;
	ea_nextp.extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
	ea_nextp.extractByHdr.ignoreProtocolValidation = 0;
	ea_nextp.extractByHdr.type = e_FM_PCD_EXTRACT_FULL_FIELD;
	ea_nextp.extractByHdr.extractByHdrType.fullField.ipv4 =
		NET_HEADER_FIELD_IPv4_PROTO;
	scheme[MAC_IPV4_TCP].keyExtractAndHashParams.extractArray[4] =
		ea_nextp;
	/* Extract field:tcp.sport */
	scheme[MAC_IPV4_TCP].keyExtractAndHashParams.extractArray[5] =
		ea_tcp_sp;
	/* Extract field:tcp.dport */
	scheme[MAC_IPV4_TCP].keyExtractAndHashParams.extractArray[6] =
		ea_tcp_dp;

	/* Distribution: Layer234 info MAC ipv4 udp */
	scheme[MAC_IPV4_UDP].alwaysDirect = 0;
	scheme[MAC_IPV4_UDP].netEnvParams.numOfDistinctionUnits = 3;
	scheme[MAC_IPV4_UDP].netEnvParams.unitIds[0] = 0;
	scheme[MAC_IPV4_UDP].netEnvParams.unitIds[1] = 1;
	scheme[MAC_IPV4_UDP].netEnvParams.unitIds[2] = 4;
	scheme[MAC_IPV4_UDP].useHash = 1;
	scheme[MAC_IPV4_UDP].baseFqid = pcd_fqids_base;
	scheme[MAC_IPV4_UDP].nextEngine = e_FM_PCD_DONE;
	scheme[MAC_IPV4_UDP].schemeCounter.update = 1;
	scheme[MAC_IPV4_UDP].schemeCounter.value = 0;
	scheme[MAC_IPV4_UDP].keyExtractAndHashParams.numOfUsedMasks = 0;
	scheme[MAC_IPV4_UDP].keyExtractAndHashParams.hashShift = 0;
	scheme[MAC_IPV4_UDP].keyExtractAndHashParams.symmetricHash = 0;
	scheme[MAC_IPV4_UDP].keyExtractAndHashParams.hashDistributionNumOfFqids
		= distNumOfQueues;
	scheme[MAC_IPV4_UDP].keyExtractAndHashParams.numOfUsedExtracts = 7;
	scheme[MAC_IPV4_UDP].numOfUsedExtractedOrs = 0;
	scheme[MAC_IPV4_UDP].netEnvParams.h_NetEnv = h_NetEnv;
	scheme[MAC_IPV4_UDP].id.relativeSchemeId = MAC_IPV4_UDP;
	/* Extract field:ethernet.src */
	scheme[MAC_IPV4_UDP].keyExtractAndHashParams.extractArray[0] =
		ea_eth_sa;
	/* Extract field:ethernet.dst */
	scheme[MAC_IPV4_UDP].keyExtractAndHashParams.extractArray[1] =
		ea_eth_da;
	/* Extract field:ipv4.src */
	scheme[MAC_IPV4_UDP].keyExtractAndHashParams.extractArray[2] =
		ea_ipv4_sa;
	/* Extract field:ipv4.dst */
	scheme[MAC_IPV4_UDP].keyExtractAndHashParams.extractArray[3] =
		ea_ipv4_da;
	/* Extract field:ipv4.nextp */
	scheme[MAC_IPV4_UDP].keyExtractAndHashParams.extractArray[4] =
		ea_nextp;
	/* Extract field:udp.sport */
	scheme[MAC_IPV4_UDP].keyExtractAndHashParams.extractArray[5] =
		ea_udp_sp;
	/* Extract field:udp.dport */
	scheme[MAC_IPV4_UDP].keyExtractAndHashParams.extractArray[6] =
		ea_udp_dp;

	bond->params.ohp->h_FmPcd = h_FmPcd;
	bond->params.ohp->h_FmPort = h_FmPort;
	bond->params.ohp->h_NetEnv = h_NetEnv;
	bond->params.ohp->prsParam = prsParam;
	bond->params.ohp->kgParam = kgParam;
	bond->params.ohp->pcdParam = pcdParam;
	bond->params.ohp->scheme = scheme;
	bond->params.ohp->netEnvParams = netEnvParams;
	hw_lag_dbg("alloc_pcd_mem() ok.\n");
	bond->params.ohp->allocated_pcd_mem = true;

	return BOND_OH_SUCCESS;

kgParam_err:
	kfree(kgParam);
prsParam_err:
	kfree(prsParam);
pcdParam_err:
	kfree(pcdParam);
netEnvParams_err:
	kfree(netEnvParams);

	return BOND_OH_ERROR;
}

int release_pcd_mem(struct bonding *bond)
{
	if (!bond->params.ohp)
		return BOND_OH_SUCCESS;

	kfree(bond->params.ohp->prsParam);
	kfree(bond->params.ohp->kgParam);
	kfree(bond->params.ohp->pcdParam);
	kfree(bond->params.ohp->scheme);
	kfree(bond->params.ohp->netEnvParams);

	bond->params.ohp->h_FmPcd = NULL;
	bond->params.ohp->h_FmPort = NULL;
	bond->params.ohp->h_NetEnv = NULL;
	bond->params.ohp->prsParam = NULL;
	bond->params.ohp->kgParam = NULL;
	bond->params.ohp->pcdParam = NULL;
	bond->params.ohp->scheme = NULL;
	bond->params.ohp->netEnvParams = NULL;
	bond->params.ohp->numberof_pre_schemes = 0;

	return BOND_OH_SUCCESS;
}

static int replace_pcd(struct fm_port *fm_port, uint8_t numOfSchemes,
		       u32 pcd_fqids_base, uint8_t distNumOfQueues,
		       struct bonding *bond)
{
	t_Handle h_FmPcd, h_FmPort, h_NetEnv;

	t_FmPcdNetEnvParams *netEnvParams;
	t_FmPcdKgSchemeParams *scheme;
	t_FmPortPcdParams *pcdParam;
	t_FmPortPcdPrsParams *prsParam;
	t_FmPortPcdKgParams *kgParam;
	int i, err, numberof_pre_schemes;

	numberof_pre_schemes = bond->params.ohp->numberof_pre_schemes;

	if (numberof_pre_schemes == numOfSchemes) {
		hw_lag_dbg("numberof_pre_schemes == numOfSchemes.\n");
		return BOND_OH_SUCCESS;
	}

	h_FmPcd = bond->params.ohp->h_FmPcd;
	h_FmPort = bond->params.ohp->h_FmPort;
	h_NetEnv = bond->params.ohp->h_NetEnv;

	netEnvParams = bond->params.ohp->netEnvParams;
	scheme = bond->params.ohp->scheme;
	pcdParam = bond->params.ohp->pcdParam;
	prsParam = bond->params.ohp->prsParam;
	kgParam = bond->params.ohp->kgParam;
	kgParam->numOfSchemes = numOfSchemes;
	hw_lag_dbg("h_FmPcd:%p, h_FmPort:%p, h_NetEnv:%p\n",
		   h_FmPcd, h_FmPort, h_NetEnv);
	hw_lag_dbg("netEnvParams:%p, scheme:%p, pcdParam:%p\n",
		   netEnvParams, scheme, pcdParam);
	hw_lag_dbg("prsParam:%p, kgParam:%p, numberof_pre_schemes:%d\n",
		   prsParam, kgParam, numberof_pre_schemes);

	if (bond->params.ohp->applied_pcd) {
		FM_PORT_Disable(h_FmPort);
		err = FM_PORT_DeletePCD(h_FmPort);
		if (err != E_OK) {
			pr_err("FM_PORT_DeletePCD errors:0x%0x\n", err);
			err = FM_PORT_Enable(h_FmPort);
			if (err == E_OK)
				hw_lag_dbg("FM_PORT_Enable() OK.\n");
			else
				pr_err("FM_PORT_Enable() err.\n");

			return BOND_OH_ERROR;
		}
		hw_lag_dbg("FM_PORT_DeletePCD OK.\n");
		err = FM_PORT_Enable(h_FmPort);
		if (err == E_OK)
			hw_lag_dbg("FM_PORT_Enable() OK.\n");
		else
			pr_err("FM_PORT_Enable() err.\n");
	}

	if (bond->params.ohp->applied_pcd) {
		for (i = 0; i < numberof_pre_schemes; i++) {
			if (kgParam->h_Schemes[i]) {
				err = FM_PCD_KgSchemeDelete(
						kgParam->h_Schemes[i]);
				if (err != E_OK) {
					pr_err("FM_PCD_KgSchemeDelete:%d", i);
					pr_err("errors:0x%0x\n", err);

					return BOND_OH_ERROR;
				}
				hw_lag_dbg("FM_PCD_KgSchemeDelete:%d ok\n", i);
				kgParam->h_Schemes[i] = NULL;
			}
		}
	}

	for (i = 0; i < numOfSchemes; i++) {
		scheme[i].baseFqid = pcd_fqids_base;
		scheme[i].keyExtractAndHashParams.hashDistributionNumOfFqids =
			distNumOfQueues;
		hw_lag_dbg("scheme[%d]->pcd_fqids_base:%d\n", i,
			   pcd_fqids_base);
		hw_lag_dbg("scheme[%d]->distNumOfQueues:%d\n", i,
			   distNumOfQueues);
	}

	for (i = 0; i < numOfSchemes; i++) {
		kgParam->h_Schemes[i] = FM_PCD_KgSchemeSet(h_FmPcd,
					   &scheme[numOfSchemes - i - 1]);

		if (!kgParam->h_Schemes[i]) {
			pr_err("error on FM_PCD_KgSchemeSet(%d)\n",
			       numOfSchemes - i - 1);

			return BOND_OH_ERROR;
		}
		hw_lag_dbg("kgParam->h_Schemes[%d]:%p.\n",
			   i, kgParam->h_Schemes[i]);
	}
	hw_lag_dbg("FM_PCD_KgSchemeSet() OK.\n");

	if (bond->params.ohp->oh_en == 1) {
		bond->params.ohp->oh_en = 0;
		err = FM_PORT_Disable(h_FmPort);
		if (err == E_OK) {
			hw_lag_dbg("FM_PORT_Disable() OK with oh_en\n");
			err = FM_PORT_SetPCD(h_FmPort, pcdParam);
			if (err == E_OK) {
				hw_lag_dbg("FM_PORT_SetPCD() OK with oh_en\n");
				err = FM_PORT_Enable(h_FmPort);
				if (err == E_OK)
					hw_lag_dbg("FM_PORT_Enable() OK.\n");
				else
					pr_err("FM_PORT_Enable() err.\n");
			} else {
				pr_err("FM_PORT_SetPCD() err in oh_en\n");
				FM_PORT_Enable(h_FmPort);
			}
		} else {
			pr_err("FM_PORT_Disable() errors with oh_en\n");
		}
		bond->params.ohp->oh_en = 1;
	} else {
		FM_PORT_Disable(h_FmPort);
		err = FM_PORT_SetPCD(h_FmPort, pcdParam);
		FM_PORT_Enable(h_FmPort);
	}
	if (GET_ERROR_TYPE(ERROR_CODE(err)) != E_OK)
		return BOND_OH_ERROR;

	bond->params.ohp->numberof_pre_schemes = numOfSchemes;
	bond->params.ohp->applied_pcd = true;

	return BOND_OH_SUCCESS;
}

/* get all offline port information from bond, including
 * dev,oh handler, PCD FQid base and PCD FQ count, then
 * get the new xmit policy, copy schemes needed from the
 * cached_scheme pointer, config PCD params, init PCD dev,
 * set PCD Net Env Characteristics, then set Keygen Scheme
 * params to the PCD dev, disable offline port, set PCD
 * params to the offline port dev, at last enable the offline
 * port.
 * this subroutine return true when it can apply PCD to
 * the offline port, otherwise return false.
 */
bool apply_pcd(struct bonding *bond, int new_xmit_policy)
{
	int true_policy;
	struct fm_port *fm_port;
	uint8_t numOfSchemes;
	u32 pcd_fqids_base;
	uint8_t distNumOfQueues;
	int err, mode;

	mode = bond->params.mode;
	if (mode != BOND_MODE_8023AD && mode != BOND_MODE_XOR) {
		hw_lag_dbg("not 802.3ad or xor mode, can't apply PCD\n");
		return false;
	}
	if (!bond->params.ohp) {
		pr_err("have not bind an OH port,\n");
		pr_err("will use software tx traffic distribution.\n");
		return false;
	}
	if (bond->slave_cnt != SLAVES_PER_BOND) {
		hw_lag_dbg("can't apply PCD, slave_cnt:%d\n", SLAVES_PER_BOND);
		return false;
	}
	if (new_xmit_policy == NO_POLICY)
		true_policy = bond->params.xmit_policy;
	else
		true_policy = new_xmit_policy;
	fm_port = bond->params.ohp->oh_config->oh_port;

	/* chang the XML PCD from user space to kernel PCD,
	 * please refer to the output of fmc host command mode
	 */
	switch (true_policy) {
	case BOND_XMIT_POLICY_LAYER23:
		numOfSchemes = 3;
		break;
	case BOND_XMIT_POLICY_LAYER34:
		numOfSchemes = 7;
		break;
	case BOND_XMIT_POLICY_LAYER2:
		numOfSchemes = 1;
		break;
	default:
		numOfSchemes = 1;
		break;
	}
	pcd_fqids_base = bond->params.ohp->pcd_fqids_base;
	distNumOfQueues = SLAVES_PER_BOND;
	hw_lag_dbg("fm_port:%p, numOfSchemes:%d, pcd_fqids_base:%d",
		   fm_port, numOfSchemes, pcd_fqids_base);
	hw_lag_dbg("distNumOfQueues:%d, bond:%p\n", distNumOfQueues, bond);
	if (!bond->params.ohp->allocated_pcd_mem) {
		err = alloc_pcd_mem(fm_port, MAX_SCHEMES, pcd_fqids_base,
				    distNumOfQueues, bond);
		if (err != BOND_OH_SUCCESS) {
			pr_err("error on alloc_pcd_mem().\n");
			return false;
		}
	}

	err = replace_pcd(fm_port, numOfSchemes, pcd_fqids_base,
			  distNumOfQueues, bond);
	if (err == BOND_OH_SUCCESS) {
		hw_lag_dbg("applied PCD.\n");
		return true;
	}
	pr_err("error on replace_pcd()\n");
	return false;
}
