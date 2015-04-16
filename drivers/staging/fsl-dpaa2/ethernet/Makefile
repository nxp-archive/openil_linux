#
# Makefile for the Freescale DPAA Ethernet controllers
#
# Copyright (C) 2014 Freescale Semiconductor, Inc.
#
# This file is released under the GPLv2
#

ccflags-y += -DVERSION=\"\"

obj-$(CONFIG_FSL_DPAA2_ETH) += fsl-ldpaa-eth.o

fsl-ldpaa-eth-objs    := ldpaa_eth.o ldpaa_ethtool.o dpni.o

#Needed by the tracing framework
CFLAGS_ldpaa_eth.o := -I$(src)

ifeq ($(CONFIG_FSL_DPAA2_ETH_GCOV),y)
	GCOV_PROFILE := y
endif
